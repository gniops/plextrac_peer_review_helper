import curses
import textwrap
import requests
import argparse
import json
import getpass
import time
import threading
import difflib
import sys
import os
import re
import tempfile
import subprocess
from copy import deepcopy
import concurrent.futures
import yaml

from models import SpacyModel, LlamaModel, CopyEditor, GrammarlyModel, extractonlytext_sendtollm, get_processed_edits
from textwrap import shorten
from pathlib import Path


os.system("stty -ixon")  # Disable CTRL+S freezing in the terminal

class PlexTracAPI:
    def __init__(self, server_fqdn, username, password, ollama_remote_url=None, tgi_remote_url=None, 
                use_llama=True, use_grammarly=False, use_html_wrapping=False):
        self.base_url = f"https://{server_fqdn}/api/v1"
        self.username = username
        self.password = password
        self.token = None # Authentication response jwt from plextrac
        self.session = requests.Session()  # Create a session object
        self.clients = None # JSON - returned from call to plexapi GET /api/v1/client/list
        
        self.client = None # JSON - returned from call to plexapi GET /api/v1/client/list for our target client
        self.client_id = None # String - Client whose report we're interested in
        self.client_name=None
        self.report_name=None

        # Original report
        self.reports=None
        self.report_info = None # JSON - return from call to plexapi GET /api/v1/client/{client_id}/reports for our target report
        self.report_id = None # String
        self.report_content = None # JSON - from call to /api/v1/client/{client_id}/report/{report}
        self.report_findings_list = None # JSON - returned from GET /api/v1/client/{client_id/report/{report_id}/flaws
        self.report_findings_content = [] # JSON [] - returned from getting each finding

        # Whether to send the html objects or extract them before sending to llm
        self.use_html_wrapping=use_html_wrapping

        # LLM Suggested fixes for report
        self.ollama_remote_url = ollama_remote_url
        self.retrieved_suggestedfixes_from_llm = False
        self.suggestedfixes_from_llm = {"executive_summary_custom_fields": None, "findings": None}
        self.visual_diff_generated=False
        self.visual_diff=None # this will hold the comparison result between original text and llm suggested text
        self.visual_diff_chunks=[] # This is for displaying each diffed finding or exec summary section during updating

        # LLM Suggested fixes via Grammarly Model (TGI Interface or locally)
        self.tgi_remote_url=tgi_remote_url
        self.copy_editor = CopyEditor()
        if use_grammarly:
            self.copy_editor.load_grammarly_model(tgi_remote_url=tgi_remote_url, model_name="grammarly/coedit-xl")
        if use_llama:
            self.copy_editor.llama=LlamaModel(ollama_remote_url=ollama_remote_url)

        self.use_llama=use_llama
        self.use_grammarly=use_grammarly

    # Authentication Functions
    # -------------------------------------------------------------------------------------------------------

    def authentication_required_decorator(func):
        """Decorator to check if authentication (self.token) is available."""
        def wrapper(self, *args, **kwargs):
            if not self.token:
                print("Authentication required.")
                return None
            return func(self, *args, **kwargs)
        return wrapper

    def authenticate(self):
        """Authenticate and retrieve JWT token."""
        auth_url = f"{self.base_url}/authenticate"
        response = self.session.post(auth_url, json={"username": self.username, "password": self.password})
        if response.status_code == 200:
            self.token = response.json().get('token')
            print("Authentication successful.")
            self.start_token_refresh()
        else:
            print(f"Authentication failed: {response.status_code} - {response.text}")
            exit(1)

    def refresh_token(self):
        """Refresh the JWT token using the refresh endpoint."""
        refresh_url = f"{self.base_url}/token/refresh"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        response = self.session.put(refresh_url, headers=headers)
        
        if response.status_code == 200:
            # Extract new token and cookie from the response
            self.token = response.json().get('token')
        else:
            print(f"Failed to refresh token: {response.status_code} - {response.text}")
            exit(1)

    def start_token_refresh(self):
        """Start a background thread to refresh the token every 10 minutes."""
        if self.token is None:
            print(" Cannot start token refresh—user is not authenticated.")
            return

        def refresh_loop():
            while self.token is not None:  # Run only if authenticated
                time.sleep(600)  # Wait 10 minutes
                self.refresh_token()

        threading.Thread(target=refresh_loop, daemon=True).start()
        print("Token refresh loop started.")
    # -------------------------------------------------------------------------------------------------------



    # Data request functions
    # -------------------------------------------------------------------------------------------------------

    @authentication_required_decorator
    def make_request_authenticated(self, method, url, headers=None, params=None, data=None, json=None):
        """Helper function to make an API request with automatic token refresh if expired."""

        headers = headers or {}
        headers["Authorization"] = f"Bearer {self.token}"

        response = self.session.request(method, url, headers=headers, params=params, data=data, json=json)

        # If token is expired (401 status), refresh and retry the request
        if response.status_code == 401:
            print("Session expired, refreshing token...")
            self.refresh_token()
            headers["Authorization"] = f"Bearer {self.token}"  # Update the headers with new token
            response = self.session.request(method, url, headers=headers, params=params, data=data)

        return response

    @authentication_required_decorator
    def get_client(self, client_name):
        """retrieves a client json blob and returns it as well as storing it in the class """
        # Fetch all clients
        clients_url = f"{self.base_url}/client/list"
        response = self.make_request_authenticated("GET", clients_url)
        if response.status_code == 200:
            self.clients = response.json()
            client = [ c for c in self.clients if c["data"][1].lower() == client_name.lower() ]
            if self.check_if_client_has_duplicate(client_name) is True:
                print("Multiple clients exist with the same name...please fix and then rerun")
                self.client_id=None
                self.client=None
                self.clients=None
            elif len(client)==1:
                self.client_id=client[0]['doc_id'][0]
                self.client=client[0]
                self.client_name=client_name
            return self.client
        else:
            print(f"Failed to retrieve clients: {response.status_code} - {response.text}")
            return None


    @authentication_required_decorator
    def get_report(self, client_name, report_name):
        """Check if a report exists for a given client by name."""
        # get client_id
        if self.client is None and self.get_client(client_name) is None:
            return None

        # Fetch reports for the client
        reports_url = f"{self.base_url}/client/{self.client_id}/reports"
        response = self.make_request_authenticated("GET", reports_url)

        target_report=[] # We make this a list to check if multiple reports with the same name exist.  So in the normal case 
                         # (e.g. single report with a given name) it should only be of length 1
        if response.status_code == 200:
            reports = response.json()
            self.reports = reports
            target_report=[ r for r in reports if r["data"][1].lower() == report_name.lower() ] 
            if self.check_if_report_has_duplicate(report_name) is True:
                print("Multiple reports exist with the same name...please fix and then rerun")
                self.report_info=None
            elif len(target_report)==1:
                self.report_info=target_report[0]
        if self.report_info is not None:
            self.report_id=self.report_info['data'][0]
            self.report_content=self.make_request_authenticated("GET", f"{self.base_url}/client/{self.client_id}/report/{self.report_id}")
            self.report_content=self.report_content.json()
            return self.report_content
        else:
            print(f"Failed to retrieve reports for client '{client_name}': {response.status_code} - {response.text}")
            return None
    
    @authentication_required_decorator
    def get_report_findings_list(self, client_name, report_name):
        """Get brief info on report findings and return as a list"""
        if self.report_content is None:
            report_response=self.get_report(client_name, report_name)
            if report_response is None:
                return None
        findings_response=self.make_request_authenticated("GET", f"{self.base_url}/client/{self.client_id}/report/{self.report_id}/flaws")
        if findings_response is not None:
            self.report_findings_list=findings_response.json()
            return self.report_findings_list
        else:
            print (f"Failed to retrieve findings list for '{client_name}': {response.status_code} - {response.text}")
            return None

    @authentication_required_decorator
    def get_report_findings_content(self, client_name, report_name):
        """Get all of the content for each report finding and return as a list"""
        if self.report_findings_list is None:
            report_response=self.get_report_findings_list(client_name, report_name)
            if report_response is None:
                return None

        for f in self.report_findings_list:
            findings_response=self.make_request_authenticated("GET", f"{self.base_url}/client/{self.client_id}/report/{self.report_id}/flaw/{f['data'][0]}")
            if findings_response is not None:
                self.report_findings_content.append( findings_response.json() )
            else:
                print (f"Failed to retrieve findings for '{client_name}': {response.status_code} - {response.text}")

        return self.report_findings_content

    @authentication_required_decorator
    def export_report(self, client_name, report_name, download_location="./"):
        """ Export a ptrac & docx copy of the report, NOTE: it's not necessary to fetch report first before exporting so fix later """
        exported_successfully=True

        if self.report_content is None:
            report_response=self.get_report(client_name, report_name)
            if report_response is None:
                return False
        ptrac=self.make_request_authenticated("GET", f"{self.base_url}/client/{self.client_id}/report/{self.report_id}/export/ptrac")
        docx=self.make_request_authenticated("GET", f"{self.base_url}/client/{self.client_id}/report/{self.report_id}/export/doc?includeEvidence=False")

        if ptrac is not None:
            ptrac=ptrac.json()
            with open(download_location+client_name+'_'+report_name+'.ptrac', 'w') as json_file:
                json.dump(ptrac, json_file)
        else:
            print ("Could not export ptrac file")
            exported_successfully=False

        if docx is not None:
            docx=docx.content
            with open(download_location+client_name+'_'+report_name+'.docx', 'wb') as bin_file:
                bin_file.write(docx)
        else:
            print ("Could not export docx file")
            exported_successfully=False

        return exported_successfully

    def check_if_report_has_duplicate(self, report_name):
        reports=[ r for r in self.reports if r["data"][1].lower() == report_name.lower() ]
        if len(reports)>1:
            return True
        return False

    def check_if_client_has_duplicate(self, client_name):
        clients=[ r for r in self.clients if r["data"][1].lower() == client_name.lower() ]
        if len(clients)>1:
            return True
        return False
    # --------------------------------------------------------------------------------------------


    # LLM Querying functions
    # --------------------------------------------------------------------------------------------
    def get_suggested_fixes_from_llm(self, use_llama=False, use_grammarly=True, prompts=None, use_html_wrapping=False):
        """Send executive summary and findings to LLM for modification suggestions (parallelized version)."""
        if not self.report_content or not self.report_findings_content:
            print("Error: Report content or findings are missing.")
            return

        # Prompts
        prompts = prompts or {
            "exec_summary": {
                "grammarly": "Make this text coherent and fix any grammar issues:",
                "llama": """You are a copy-editor. Improve clarity, flow, grammar, and professionalism while preserving meaning and any URLs/HTML tags.

    OUTPUT RULES:
    - Output ONLY the revised text.
    - Do NOT add any explanations, headings, labels, or lead-ins (e.g., “Here is the edited text:”).
    - Do NOT wrap the output in quotes or Markdown/code fences.
    - Keep all HTML tags that are present in the input unless they are clearly broken.

    Use these Strict instructions:
    - Do not add, remove, or rewrite sentences.
    - Do not invent any new information or make assumptions.
    - Only fix grammar, punctuation, and typos.
    - Remove roundabout phrases like: "during this engagement", "in order to", etc.
    - If a number is written as "five (5)", convert it to just "five". Do not change actual dates.
    - Do not add or remove any HTML tags, including <code>...</code> or <span>...</span>.
    - Keep company names capitalized as: PentestCompany
    - Replace verbose technical phrases with standard abbreviations, **only if they already exist in the text**.

    Return only the edited version of the input text, nothing more:"""
            },
            "finding_title": {
                "grammarly": "Refine the following title for clarity and readability while preserving its original intent:",
                "llama": """You are a copy-editor. Improve clarity, flow, grammar, and professionalism while preserving meaning and any URLs/HTML tags.
    OUTPUT RULES:
    - Output ONLY the revised text.
    - Do NOT add any explanations, headings, labels, or lead-ins (e.g., “Here is the edited text:”).
    - Do NOT wrap the output in quotes or Markdown/code fences.
    - Keep all HTML tags that are present in the input unless they are clearly broken.

    Use these Strict instructions:

    - Improve the finding title while keeping changes minimal.
    - Do not add words like "Vulnerability Assessment" or change the title format unnecessarily.
    - Do not introduce new terms or change their meaning.
    - Capitalize the first letter of each word.
    Return the text and nothing more:"""
            },
            "finding_body": {
                "grammarly": "Make this text coherent and fix any grammar issues:",
                "llama": """You are a copy-editor. Improve clarity, flow, grammar, and professionalism while preserving meaning and any URLs/HTML tags.

    OUTPUT RULES:
    - Output ONLY the revised text.
    - Do NOT add any explanations, headings, labels, or lead-ins (e.g., “Here is the edited text:”).
    - Do NOT wrap the output in quotes or Markdown/code fences.
    - Keep all HTML tags that are present in the input unless they are clearly broken.

    Use these Strict instructions:
    - Do not add, remove, or rewrite sentences.
    - Do not invent any new information or make assumptions.
    - Only fix grammar, punctuation, and typos.
    - Remove roundabout phrases like: "during this engagement", "in order to", etc.
    - If a number is written as "five (5)", convert it to just "five". Do not change actual dates.
    - Do not add or remove any HTML tags, including <code>...</code> or <span>...</span>.
    - Keep company names capitalized as: PentestCompany
    - Replace verbose technical phrases with standard abbreviations, **only if they already exist in the text**.

    Return only the edited version of the input text, nothing more:"""
            }
        }

        # --- Process Executive Summary (Sequential) ---
        modified_exec_summary = []
        for field_execsummary_narrative in self.report_content.get("exec_summary", {}).get("custom_fields", []):
            modified_field = field_execsummary_narrative.copy()

            edits = get_processed_edits(
                field_execsummary_narrative.get("text", ""),
                self,
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["exec_summary"],
                use_html_wrapping=self.use_html_wrapping
            )

            modified_field["text"] = "".join(edits)
            modified_exec_summary.append(modified_field)

        # --- Helper to process a single finding ---
        def process_single_finding(finding):
            modified_finding = finding.copy()

            title_edits = self.copy_editor.get_edits(
                finding.get("title", ""),
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["finding_title"]
            )

            description_edits = get_processed_edits(
                finding.get("description", ""),
                self,
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["finding_body"],
                use_html_wrapping=self.use_html_wrapping
            )

            recommendations_edits = get_processed_edits(
                finding.get("recommendations", ""),
                self,
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["finding_body"],
                use_html_wrapping=self.use_html_wrapping
            )

            guidance_edits = get_processed_edits(
                finding.get("fields", {}).get("guidance", {}).get("value", ""),
                self,
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["finding_body"],
                use_html_wrapping=self.use_html_wrapping
            )

            reproduction_edits = get_processed_edits(
                finding.get("fields", {}).get("reproduction_steps", {}).get("value", ""),
                self,
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts=prompts["finding_body"],
                use_html_wrapping=self.use_html_wrapping
            )

            modified_finding.update({
                "title": "".join(title_edits),
                "description": "".join(description_edits),
                "recommendations": "".join(recommendations_edits)
            })
            if "guidance" in modified_finding.get("fields", {}):
                modified_finding["fields"]["guidance"]["value"] = "".join(guidance_edits)
            if "reproduction_steps" in modified_finding.get("fields", {}):
                modified_finding["fields"]["reproduction_steps"]["value"] = "".join(reproduction_edits)

            return modified_finding

        # --- Process Findings (Parallel!) ---
        modified_findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_single_finding, finding) for finding in self.report_findings_content]
            for future in concurrent.futures.as_completed(futures):
                modified_findings.append(future.result())

        # Sort back to original order if needed
        modified_findings = sorted(modified_findings, key=lambda x: x["flaw_id"])

        # --- Save the suggestions ---
        self.suggestedfixes_from_llm = {
            "executive_summary_custom_fields": {"custom_fields": modified_exec_summary},
            "findings": modified_findings
        }

        self.retrieved_suggestedfixes_from_llm = True
        print("LLM and Grammarly suggestions retrieved successfully.")
        time.sleep(2)

    def generate_executive_summary(self, template_path: str, use_llama=True, use_grammarly=False):
        """
        Build a brand‑new executive summary from report_findings_content and
        a YAML/JSON template.  Returns the list of {'label','text', 'id'} dicts.
        """

        def first_n_sentences(text: str, n: int = 3) -> str:
            sentences = re.split(r"(?<=[.!?])\s+", text.strip())
            return " ".join(sentences[:n])

        def format_findings_compact(findings: list[dict], max_chars=12000) -> str:
            blocks = [
                f"{f['title']}"
                for f in findings
            ]
            return "\n".join(blocks)[:max_chars]

        def format_findings_as_report(findings: list[dict], max_chars=12000) -> str:
            blocks = []
            for f in findings:
                title = f.get("title", "Untitled")
                severity = f.get("severity", "Unknown")
                desc = f.get("description", "").strip()
                recs = f.get("recommendations", "").strip()

                block = f"""Title: {title}
        Severity: {severity}
        Description:
        {desc if desc else '(No description provided)'}

        Recommendations:
        {recs if recs else '(No recommendations provided)'}
        ---
        """
                blocks.append(block.strip())

            result = "\n\n".join(blocks)
            return result[:max_chars]

        if not self.report_findings_content:
            raise ValueError("Findings not loaded. Run get_report_findings_content()")

        template = load_template_execsummary(template_path) # small helper to read YAML
        findings_for_prompt = format_findings_compact(self.report_findings_content)

        new_sections = []
        for section in template:
            prompt_template = section["system_prompt"]
            prompt = prompt_template.replace("{{FINDINGS_JSON_SNIPPET_HERE}}", findings_for_prompt)

            generated_text = self.copy_editor.get_edits(
                prompt,                        # treat full prompt as “text” to LLM
                use_llama=use_llama,
                use_grammarly=use_grammarly,
                prompts={"llama": prompt, "grammarly": prompt}
            )[0]                              # join omitted because get_edits returns list

            log_llm_interaction(
                section=section['id'],
                field_id=None,
                model=", ".join(m for m, enabled in [("llama3:8b-instruct-fp16", use_llama), 
                                                     ("grammarly/coedit-xl", use_grammarly)] if enabled),
                prompt=prompt,
                response=generated_text
            )

            new_sections.append({
                "id": section["id"],          # keep deterministic IDs for updates later
                "label": section["label"],
                "text": generated_text.strip()
            })

        return new_sections

    # --------------------------------------------------------------------------------------------


    # Report update functions for suggestions retrieved from LLM
    # ---------------------------------------------------------------------------------------------

    @authentication_required_decorator
    def update_executive_summary(self, field_id, updated_text):
        """
        Update a specific executive summary field in PlexTrac and, on success,
        log *all* exec summary fields (original+modified) so the audit log is complete.
        """
        client_id = self.client_id
        report_id = self.report_id

        if not client_id or not report_id:
            print("Error: Client ID or Report ID is missing.")
            return False

        if not self.report_content:
            print("Error: Full report content is missing. Fetch it before updating.")
            return False

        existing_custom_fields = self.report_content.get("exec_summary", {}).get("custom_fields", [])
        if not isinstance(existing_custom_fields, list):
            print("Error: exec_summary.custom_fields is missing or not a list.")
            return False

        # ----- 1) Precompute originals + would-be updates (no mutation yet) -----
        audit_entries = []            # list of dicts to feed log_change() after success
        modified_custom_fields = []   # list for self.report_content mutation
        field_updated = False
        target_id_str = str(field_id)

        for f in existing_custom_fields:
            fid = str(f.get("id"))
            original_text = f.get("text", "")

            if fid == target_id_str:
                # This is the one we are updating
                new_text = updated_text
                field_updated = True

                mf = f.copy()
                mf["text"] = updated_text
                modified_custom_fields.append(mf)
                audit_entries.append({
                    "section": "executive_summary",
                    "field_id": fid,
                    "original": original_text,
                    "modified": new_text,
                    "accepted": True,
                })
            else:
                # Not touched
                new_text = original_text
                modified_custom_fields.append(f)

        if not field_updated:
            print(f"Error: No executive summary field found with ID {field_id}.")
            return False

        # ----- 2) Mutate local copy that we'll send to the server -----
        self.report_content["exec_summary"]["custom_fields"] = modified_custom_fields
        updated_report = self.report_content.copy()

        # ----- 3) PUT update first -----
        url = f"{self.base_url}/client/{client_id}/report/{report_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

        try:
            response = self.make_request_authenticated("PUT", url, headers=headers, json=updated_report)

            # ----- 4) Only log after a successful update -----
            if response.status_code == 200:
                for e in audit_entries:
                    log_change(
                        e["section"],
                        e["field_id"],
                        e["original"],
                        e["modified"],
                        e["accepted"]
                    )
                print(f"Executive summary field {field_id} updated successfully.")
                time.sleep(3)
                return True
            else:
                print(f"Error updating field {field_id}: {response.status_code}, {response.text}")
                time.sleep(3)
                return False

        except requests.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(3)
            return False


    @authentication_required_decorator
    def update_finding(
        self,
        finding_id,
        updated_title=None,
        updated_description=None,
        updated_recommendations=None,
        updated_guidance=None,
        updated_reproduction_steps=None,
    ):
        """
        Update a specific finding in PlexTrac and, on success, log only the fields
        the user actually accepted (i.e., the ones passed in and changed).
        """
        client_id = self.client_id
        report_id = self.report_id

        if not client_id or not report_id:
            print("Error: Client ID or Report ID is missing.")
            time.sleep(3)
            return False

        findings = self.report_findings_content or []
        # ---- find target finding ----
        target = None
        for f in findings:
            if str(f.get("id")) == str(finding_id):
                target = f
                break

        if target is None:
            print(f"Error: No finding found with ID {finding_id}.")
            time.sleep(3)
            return False

        # ---- snapshot originals (strings only) BEFORE mutation ----
        def _nested(d, *path, default=""):
            cur = d
            for p in path:
                if not isinstance(cur, dict) or p not in cur:
                    return default
                cur = cur[p]
            return cur

        originals = {
            "title": target.get("title", ""),
            "description": target.get("description", ""),
            "recommendations": target.get("recommendations", ""),
            "guidance": _nested(target, "fields", "guidance", "value", default=""),
            "reproduction_steps": _nested(target, "fields", "reproduction_steps", "value", default=""),
        }

        # ---- build list of accepted updates (only if param is provided AND changed) ----
        updates = []  # each: (log_label, path_key, new_value, original_value)
        if updated_title is not None and updated_title != originals["title"]:
            updates.append(("finding title", ("title",), updated_title, originals["title"]))
        if updated_description is not None and updated_description != originals["description"]:
            updates.append(("finding description", ("description",), updated_description, originals["description"]))
        if updated_recommendations is not None and updated_recommendations != originals["recommendations"]:
            updates.append(("finding recommendations", ("recommendations",), updated_recommendations, originals["recommendations"]))
        if updated_guidance is not None and updated_guidance != originals["guidance"]:
            updates.append(("finding guidance", ("fields", "guidance", "value"), updated_guidance, originals["guidance"]))
        if updated_reproduction_steps is not None and updated_reproduction_steps != originals["reproduction_steps"]:
            updates.append(("finding reproduction_steps", ("fields", "reproduction_steps", "value"), updated_reproduction_steps, originals["reproduction_steps"]))

        if not updates:
            print("No changes to apply for this finding.")
            time.sleep(2)
            return False

        # ---- make a deep copy to avoid mutating nested dicts in the original ----
        modified = deepcopy(target)

        # ---- apply accepted updates to the deep copy ----
        for _, path, new_val, _orig in updates:
            if len(path) == 1:
                modified[path[0]] = new_val
            else:
                cur = modified
                for k in path[:-1]:
                    if k not in cur or not isinstance(cur[k], dict):
                        cur[k] = {}
                    cur = cur[k]
                cur[path[-1]] = new_val

        # ---- PUT the single finding update ----
        url = f"{self.base_url}/client/{client_id}/report/{report_id}/flaw/{finding_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

        try:
            response = self.make_request_authenticated("PUT", url, headers=headers, json=modified)
            if response.status_code == 200:
                # update in-memory finding (so UI reflects new text)
                for i, f in enumerate(self.report_findings_content):
                    if str(f.get("id")) == str(finding_id):
                        self.report_findings_content[i] = modified
                        break

                # ---- log ONLY the accepted updates after success ----
                for log_label, _path, new_val, orig_val in updates:
                    log_change(log_label, finding_id, orig_val, new_val, accepted=True)

                print(f"Finding {finding_id} updated successfully.")
                time.sleep(2)
                return True
            else:
                print(f"Error updating finding {finding_id}: {response.status_code}, {response.text}")
                time.sleep(3)
                return False

        except requests.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(3)
            return False


    # ---------------------------------------------------------------------------------------------

    # Report Display Functions
    # These functions can be called after all of the necessary report items are downloaded
    # --------------------------------------------------------------------------------------------------------------
    def get_local_exec_summary(self, original=True):
        """Extract the executive summary from a report and return it. - suitable for display in curses"""
        executive_summary = []
        if self.report_content is not None:
            if self.report_content.get("exec_summary"):
                # Check if 'custom_fields' exists and is a list
                custom_fields = self.report_content.get("exec_summary").get('custom_fields', []) if original is True else self.suggestedfixes_from_llm["executive_summary_custom_fields"]["custom_fields"]
                if custom_fields:
                    for field in custom_fields:
                        executive_summary.append( field.get('label', 'No label available')+'\n----------------------\n'+
                                                  field.get('text', 'No text available')+"\n")
                else:
                    print(f"No custom fields found in the executive summary.")
            else:
                print(f"No executive summary found.")
        return executive_summary

    
    def get_local_findings(self, original=True):
        """ return local copy of findings, original or llm generated - suitable for display in curses """
        report_findings_content=[]

        findings=self.report_findings_content if original is True else self.suggestedfixes_from_llm["findings"]
        if findings is not None:
            for f in findings:
                report_findings_content.append( f"Title: {f['title']}\n" +
                                                '---------------------------------------------\n\n' +
                                                f"\n*Description: {f['description']}\n\n" +
                                                f"\n\n*Recommendations: {f['recommendations']}\n\n" +
                                                f"\n\n*Guidance: {f['fields'].get('guidance', {}).get('value', '')}\n\n" +
                                                f"\n\n*Reproduction Steps: {f['fields'].get('reproduction_steps', {}).get('value', '')}\n\n"
                                             )
        return report_findings_content


    def generate_visual_reportdiff(self):
        """Generate a word-based diff between the original report and LLM-suggested, formatted for curses, with full and chunked storage."""
        exec_summary_diffs = []
        report_findings_diffs = []
        self.visual_diff_chunks = {}  # New: chunked diffs per field/finding

        def word_diff(original, modified):
            """Generate a sentence-based diff for curses display."""
            diff = difflib.ndiff(
                re.split(r'(?<=\.)\s*', original.strip()),
                re.split(r'(?<=\.)\s*', modified.strip())
            )
            formatted_diff = []

            for token in diff:
                if token.startswith("+ "):
                    formatted_diff.append(("add", token[2:]))
                elif token.startswith("- "):
                    formatted_diff.append(("remove", token[2:]))
                else:
                    formatted_diff.append(("normal", token[2:]))
            return formatted_diff

        # Diff Executive Summary
        original_execsummary = self.report_content.get("exec_summary", {}).get("custom_fields", [])
        modified_execsummary = self.suggestedfixes_from_llm.get("executive_summary_custom_fields", {}).get("custom_fields", [])

        for idx, (i1, i2) in enumerate(zip(original_execsummary, modified_execsummary)):
            label = i1.get("label", "Unknown Section")
            exec_summary_diffs.append(("title", f"=== {label} ==="))

            diffs = word_diff(i1.get("text", ""), i2.get("text", ""))
            exec_summary_diffs.extend(diffs)
            exec_summary_diffs.append(("normal", ""))  # Blank line for spacing

            # Store chunk
            self.visual_diff_chunks[f"exec_summary_{idx}"] = [("title", f"=== {label} ===")] + diffs

        # Diff Findings
        findings = self.report_findings_content
        modified_findings = self.suggestedfixes_from_llm.get("findings", [])

        for idx, (i1, i2) in enumerate(zip(findings, modified_findings)):
            finding_title = i1.get("title", "Untitled Finding")
            report_findings_diffs.append(("title", f"=== {finding_title} ==="))

            for section in ["title", "description", "recommendations", "guidance", "reproduction_steps"]:
                report_findings_diffs.append(("section", f"{section.capitalize()}:"))

                if section not in ["guidance", "reproduction_steps"]:
                    diffs = word_diff(i1.get(section, ""), i2.get(section, ""))
                else:
                    diffs = word_diff(
                        i1.get("fields", {}).get(section, {}).get("value", ""),
                        i2.get("fields", {}).get(section, {}).get("value", "")
                    )

                report_findings_diffs.extend(diffs)
                report_findings_diffs.append(("normal", ""))  # Blank line for spacing

                # Store chunk
                self.visual_diff_chunks[f"finding_{idx}_{section}"] = [("section", f"{section.capitalize()}:")] + diffs

        # Store full diff for full view mode
        self.visual_diff = exec_summary_diffs + report_findings_diffs
        self.visual_diff_generated = True

        return self.visual_diff
    # --------------------------------------------------------------------------------------------------------------


# User Interface 
# ------------------------------------------------------------------------------------------
def interactive_text_viewer(stdscr, pages):
    """Curses-based interactive viewer with text wrapping and vertical scrolling."""
    curses.curs_set(0)
    page_index = 0
    current_view = "ORIGINAL VIEW-"
    scroll_offset = 0  # Track vertical scrolling

    while True:
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()

        # Message at the top of the window
        top_message = f"Page {page_index + 1}/{len(pages)} (q-quit, c-gen/regen exec summary, r-get llm suggestions, p-view suggestions, o-view original, d-view diffs, u-import updates to plextrac)"
        stdscr.addstr(0, 0, current_view + top_message, curses.A_BOLD)

        # Wrap text properly
        raw_page = "\n".join(pages[page_index])
        formatted = soft_format_html_for_terminal(raw_page)
        wrapped_lines = []

        for paragraph in formatted.splitlines():
            wrapped_lines.extend(textwrap.wrap(paragraph, width=max_x - 4))

        total_lines = len(wrapped_lines)
        visible_lines = wrapped_lines[scroll_offset: scroll_offset + max_y - 3]  # Leave space for header

        # Display visible text
        for i, line in enumerate(visible_lines):
            stdscr.addstr(i + 2, 2, line)

        stdscr.refresh()
        key = stdscr.getch()

        # Quit viewer
        if key == ord('q'):
            break
        # Scroll down
        elif key == curses.KEY_DOWN and scroll_offset < total_lines - (max_y - 3):
            scroll_offset += 1
        # Scroll up
        elif key == curses.KEY_UP and scroll_offset > 0:
            scroll_offset -= 1
        # Next page
        elif key in (curses.KEY_RIGHT, ord('l')) and page_index < len(pages) - 1:
            page_index += 1
            scroll_offset = 0  # Reset scrolling on new page
        # Previous page
        elif key in (curses.KEY_LEFT, ord('h')) and page_index > 0:
            page_index -= 1
            scroll_offset = 0  # Reset scrolling on new page
        # Get LLM suggestions
        elif key == ord('r'):
            stdscr.addstr(1, 0, "Sending report to LLM for suggestions...", curses.A_BOLD)
            stdscr.refresh()
            api.get_suggested_fixes_from_llm(use_llama=api.use_llama, use_grammarly=api.use_grammarly)
            api.generate_visual_reportdiff()
        # View LLM suggestions
        elif key == ord('p') and api.retrieved_suggestedfixes_from_llm:
            pages = generate_paginated_text(api.get_local_exec_summary(original=False) + api.get_local_findings(original=False))
            current_view = "LLM VIEW-"
            page_index = 0
            scroll_offset = 0
        # View Diff mode
        elif key == ord('d') and api.visual_diff_generated:
            display_visual_diff_mode(stdscr, api.visual_diff)
        # View original report
        elif key == ord('o'):
            pages = generate_paginated_text(api.get_local_exec_summary(original=True) + api.get_local_findings(original=True))
            current_view = "ORIGINAL VIEW-"
            page_index = 0
            scroll_offset = 0
        # Import updates into PlexTrac
        elif key == ord('u') and api.retrieved_suggestedfixes_from_llm:
            import_llm_suggestions(api, stdscr, max_x, max_y)
        # Use llm to generate executive summary from the findings list
        elif key == ord('c') and api.retrieved_suggestedfixes_from_llm:
            stdscr.addstr(1, 0, "Generating executive summary with LLM...", curses.A_BOLD)
            stdscr.refresh()
            new_sections=api.generate_executive_summary("templates/execsummary.yml", use_llama=api.use_llama, use_grammarly=api.use_grammarly)
            api.suggestedfixes_from_llm["executive_summary_custom_fields"] = {
                "custom_fields": new_sections
            }
            api.generate_visual_reportdiff()


def import_llm_suggestions(api, stdscr, max_x, max_y):
    """Use precomputed visual_diff_chunks to review and apply suggestions."""
    if not api.suggestedfixes_from_llm:
        print("Error: No LLM suggestions loaded.")
        return

    curses.curs_set(0)  # Hide cursor

    # === EXECUTIVE SUMMARY FIRST ===
    stdscr.clear()
    stdscr.addstr(0, 2, "Reviewing Executive Summary Sections (Update Mode)")
    stdscr.refresh()
    time.sleep(1)

    exec_summary_fields = deepcopy(api.report_content.get("exec_summary", {}).get("custom_fields", []))
    updated_exec_summary_fields = deepcopy(api.suggestedfixes_from_llm.get("executive_summary_custom_fields", {}).get("custom_fields", []))

    for idx, (field, updated_field) in enumerate(zip(exec_summary_fields, updated_exec_summary_fields)):
        field_id = field.get("id")
        key = f"exec_summary_{idx}"
        diff_lines = api.visual_diff_chunks.get(key, [])

        if not diff_lines:
            continue

        field_label = field.get("label", f"Executive Summary Section {idx}")
        action = display_visual_diff_chunk(stdscr, diff_lines, field_label=field_label)

        if action == "q":
            return  # Quit entire update mode immediately

        if action == "a":
            field["text"] = updated_field["text"]
            api.update_executive_summary(field_id, field["text"])
        elif action == "e":
            edited_text = open_vi_to_edit(updated_field["text"])
            # REINITIALIZE curses here:
            curses.cbreak()
            curses.noecho()
            stdscr.keypad(True)
            curses.curs_set(0)
            field["text"] = edited_text
            api.update_executive_summary(field_id, edited_text)
        # if "s" (skip), do nothing

    # === THEN FINDINGS ===
    stdscr.clear()
    stdscr.addstr(0, 2, "Reviewing Findings Sections (Update Mode)")
    stdscr.refresh()
    time.sleep(1)

    findings = deepcopy(api.report_findings_content)
    updated_findings = deepcopy(api.suggestedfixes_from_llm.get("findings", []))

    fields_to_review = ["title", "description", "recommendations", "guidance", "reproduction_steps"]

    for idx, (finding, updated_finding) in enumerate(zip(findings, updated_findings)):
        finding_id = finding.get("flaw_id")

        for field in fields_to_review:
            if field in ["guidance", "reproduction_steps"]:
                original_text = finding.get("fields", {}).get(field, {}).get("value", "")
                updated_text = updated_finding.get("fields", {}).get(field, {}).get("value", "")
            else:
                original_text = finding.get(field, "")
                updated_text = updated_finding.get(field, "")

            if not original_text.strip() and not updated_text.strip():
                continue

            key = f"finding_{idx}_{field}"
            diff_lines = api.visual_diff_chunks.get(key, [])

            if not diff_lines:
                continue

            field_label = f"Finding {idx} - {field.capitalize()}"
            action = display_visual_diff_chunk(stdscr, diff_lines, field_label=field_label)

            if action == "q":
                return  # 🔥 Quit entire update mode immediately

            if action == "a":
                if field in ["guidance", "reproduction_steps"]:
                    finding["fields"][field]["value"] = updated_text
                else:
                    finding[field] = updated_text

                api.update_finding(
                    finding_id,
                    updated_title=finding.get("title"),
                    updated_description=finding.get("description"),
                    updated_recommendations=finding.get("recommendations"),
                    updated_guidance=finding.get("fields", {}).get("guidance", {}).get("value", None),
                    updated_reproduction_steps=finding.get("fields", {}).get("reproduction_steps", {}).get("value", None)
                )
            elif action == "e":
                edited_text = open_vi_to_edit(updated_text)
                #  REINITIALIZE curses here:
                curses.cbreak()
                curses.noecho()
                stdscr.keypad(True)
                curses.curs_set(0)

                if field in ["guidance", "reproduction_steps"]:
                    finding["fields"][field]["value"] = edited_text
                else:
                    finding[field] = edited_text

                api.update_finding(
                    finding_id,
                    updated_title=finding.get("title"),
                    updated_description=finding.get("description"),
                    updated_recommendations=finding.get("recommendations"),
                    updated_guidance=finding.get("fields", {}).get("guidance", {}).get("value", None),
                    updated_reproduction_steps=finding.get("fields", {}).get("reproduction_steps", {}).get("value", None)
                )
            # if "s" (skip), do nothing

    stdscr.clear()
    stdscr.addstr(0, 2, "Report review complete!")
    stdscr.refresh()
    time.sleep(2)


def open_vi_to_edit(text):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(text.encode('utf-8'))
        temp_file.close()

        subprocess.run(['vi', temp_file.name])

        with open(temp_file.name, 'r', encoding='utf-8') as f:
            edited_content = f.read()

        os.remove(temp_file.name)

    return edited_content

def paginate_text(text, max_lines=300):
    """Splits long text into pages of a fixed number of lines."""
    lines = text.split("\n")
    return [lines[i:i+max_lines] for i in range(0, len(lines), max_lines)]

def generate_paginated_text(all_text, max_lines=300):
    paginated_text = [paginate_text(text, max_lines=max_lines) for text in all_text]
    paginated_text = [page for sublist in paginated_text for page in sublist]
    return paginated_text

def display_visual_diff_chunk(stdscr, visual_diff_chunk, field_label):
    """Display a single field's diff chunk using true wrapped lines scrolling."""
    stdscr.clear()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Additions
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)    # Deletions
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Titles
    curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Sections
    curses.curs_set(0)  # Hide cursor

    # Re-enable mouse support
    curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
    curses.mouseinterval(0)

    max_y, max_x = stdscr.getmaxyx()
    offset = 0

    # Flatten the chunk into real wrapped screen lines
    all_wrapped_lines = []
    for diff_type, text in visual_diff_chunk:
        wrapped = textwrap.wrap(text, width=max_x - 4)
        for wline in wrapped:
            all_wrapped_lines.append((diff_type, wline))

    while True:
        stdscr.clear()

        # Header
        stdscr.addstr(0, 2, f"Reviewing: {field_label} (Update mode only: a=accept, s=skip, e=-edit and accept-), up-down to scroll, q-quit", curses.A_BOLD)

        # Draw visible window of lines
        current_line_y = 2
        visible_lines = all_wrapped_lines[offset:offset + (max_y - 3)]

        for diff_type, line in visible_lines:
            color = curses.color_pair(1) if diff_type == "add" else \
                    curses.color_pair(2) if diff_type == "remove" else \
                    curses.color_pair(3) if diff_type == "title" else \
                    curses.color_pair(4) if diff_type == "section" else 0

            if current_line_y < max_y - 1:
                stdscr.addstr(current_line_y, 2, line, color)
                current_line_y += 1

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_MOUSE:
            try:
                _, mx, my, _, mouse_state = curses.getmouse()
                if mouse_state & curses.BUTTON4_PRESSED:  # Scroll up
                    if offset > 0:
                        offset -= 1
                elif mouse_state & curses.BUTTON5_PRESSED:  # Scroll down
                    if offset < max(len(all_wrapped_lines) - (max_y - 3), 0):
                        offset += 1
            except curses.error:
                pass

        elif key in [ord('a'), ord('s'), ord('e')]:
            return chr(key)
        elif key == ord('q'):
            return "q"
        elif key == curses.KEY_DOWN and offset < max(len(all_wrapped_lines) - (max_y - 3), 0):
            offset += 1
        elif key == curses.KEY_UP and offset > 0:
            offset -= 1


def display_visual_diff_mode(stdscr, visual_diff):
    """Display the word-based, colorized diff in a scrollable curses interface."""
    stdscr.clear()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Additions
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)  # Deletions
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Titles
    curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Sections
    curses.curs_set(0)  # Hide cursor

    max_y, max_x = stdscr.getmaxyx()
    pad_height = max(len(visual_diff) * 2, max_y) + 10  # Ensure enough space
    pad = curses.newpad(pad_height, max_x)
    y_offset = 0  # Scroll position
    line_num = 0  # Track line position

    # Render text into the pad
    for diff_type, text in visual_diff:
        # Wrap text properly to fit screen width
        wrapped_lines = textwrap.wrap(text, width=max_x - 4)

        # Apply color formatting
        color = curses.color_pair(1) if diff_type == "add" else \
                curses.color_pair(2) if diff_type == "remove" else \
                curses.color_pair(3) if diff_type == "title" else \
                curses.color_pair(4) if diff_type == "section" else 0

        for line in wrapped_lines:
            if line_num < pad_height - 1:
                pad.addstr(line_num, 2, line, color)
                line_num += 1  # Move to next line normally

    while True:
        stdscr.refresh()  # Keep background stable
        stdscr.addstr(0, 0, "DIFF View (q-back, up arrow-scroll up, down arrow-scroll down, a-accept, e-edit further, s-skip update)")

        # Refresh pad display with correct offset
        pad.refresh(y_offset, 0, 1, 0, max_y - 1, max_x - 1)

        key = stdscr.getch()
        if key == ord('q'):  # Quit the diff view
            break
        elif key in [ord('a'), ord('s'), ord('e')]:
            return chr(key)
        elif key == curses.KEY_DOWN and y_offset < max(pad_height - max_y, 0):
            y_offset += 1  # Scroll down (prevent over-scrolling)
        elif key == curses.KEY_UP and y_offset > 0:
            y_offset -= 1  # Scroll up


def is_executive_summary_unchanged(api, narrative_id):
    """
    Finds and compares the original and modified executive summary narratives for a given ID.

    :param narrative_id: ID of the narrative text to check.
    :return: True if unchanged, False if modified.
    """
    # Find the original narrative by ID
    original_narrative = next((item for item in api.report_content["exec_summary"]["custom_fields"] if item.get("id") == narrative_id), None)
    
    # Find the modified narrative by ID
    modified_narrative = next((item for item in api.suggestedfixes_from_llm["executive_summary_custom_fields"]["custom_fields"] if item.get("id") == narrative_id), None)

    # If either is missing, consider them different
    if original_narrative is None or modified_narrative is None:
        return False

    # Compare the text fields
    return original_narrative.get("text", "") == modified_narrative.get("text", "")

def is_finding_title_unchanged(api, finding_id):
    """
    Finds and compares the original and modified finding titles for a given ID.

    :param api: API instance containing report data.
    :param finding_id: ID of the finding to check.
    :return: True if unchanged, False if modified.
    """
    original_finding = next((item for item in api.report_findings_content if item.get("flaw_id") == finding_id), None)
    modified_finding = next((item for item in api.suggestedfixes_from_llm["findings"] if item.get("flaw_id") == finding_id), None)

    if original_finding is None or modified_finding is None:
        return False

    return original_finding.get("title", "") == modified_finding.get("title", "")

def is_finding_description_unchanged(api, finding_id):
    """
    Finds and compares the original and modified finding descriptions for a given ID.

    :param api: API instance containing report data.
    :param finding_id: ID of the finding to check.
    :return: True if unchanged, False if modified.
    """
    original_finding = next((item for item in api.report_findings_content if item.get("flaw_id") == finding_id), None)
    modified_finding = next((item for item in api.suggestedfixes_from_llm["findings"] if item.get("flaw_id") == finding_id), None)

    if original_finding is None or modified_finding is None:
        return False

    return original_finding.get("description", "") == modified_finding.get("description", "")


def is_finding_recommendations_unchanged(api, finding_id):
    """
    Finds and compares the original and modified finding recommendations for a given ID.

    :param api: API instance containing report data.
    :param finding_id: ID of the finding to check.
    :return: True if unchanged, False if modified.
    """
    original_finding = next((item for item in api.report_findings_content if item.get("flaw_id") == finding_id), None)
    modified_finding = next((item for item in api.suggestedfixes_from_llm["findings"] if item.get("flaw_id") == finding_id), None)

    if original_finding is None or modified_finding is None:
        return False

    return original_finding.get("recommendations", "") == modified_finding.get("recommendations", "")


def is_finding_guidance_unchanged(api, finding_id):
    """
    Finds and compares the original and modified finding guidance for a given ID.

    :param api: API instance containing report data.
    :param finding_id: ID of the finding to check.
    :return: True if unchanged, False if modified.
    """
    original_finding = next((item for item in api.report_findings_content if item.get("flaw_id") == finding_id), None)
    modified_finding = next((item for item in api.suggestedfixes_from_llm["findings"] if item.get("flaw_id") == finding_id), None)

    if original_finding is None or modified_finding is None:
        return False

    return original_finding.get("fields","").get("guidance", {}).get("value","")==modified_finding.get("fields","").get("guidance", {}).get("value","")

def is_finding_reproduction_steps_unchanged(api, finding_id):
    """
    Finds and compares the original and modified finding reproduction_steps for a given ID.

    :param api: API instance containing report data.
    :param finding_id: ID of the finding to check.
    :return: True if unchanged, False if modified.
    """
    original_finding = next((item for item in api.report_findings_content if item.get("flaw_id") == finding_id), None)
    modified_finding = next((item for item in api.suggestedfixes_from_llm["findings"] if item.get("flaw_id") == finding_id), None)

    if original_finding is None or modified_finding is None:
        return False

    return original_finding.get("fields","").get("reproduction_steps", {}).get("value","") == modified_finding.get("fields","").get("reproduction_steps", {}).get("value","") 


def log_change(section, field_id, original_text, modified_text, accepted, LOG_FILE="peer_review_log.json"):
    """Log accepted/rejected changes during peer review."""
    log_entry = {
        "section": section,
        "field_id": field_id,
        "original": original_text,
        "modified": modified_text,
        "accepted": accepted
    }

    try:
        # Load existing log data
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []  # Start fresh if no log exists or file is corrupted

    logs.append(log_entry)

    # Save updated logs
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    print(f"Logged change: {log_entry}")

def log_llm_interaction(
    section: str,
    field_id: str | int | None,
    model: str,
    prompt: str,
    response: str,
    LOG_FILE: str = "llm_interaction_log.json",
    max_chars: int = 2000,   # truncate huge prompts/responses
) -> None:
    """
    Append a single LLM call (prompt + response) to a JSON log file.
    Mirrors the structure of `log_change()` for consistency.

    Args:
        section   – 'exec_summary', 'finding_title', etc.
        field_id  – ID of the field/finding when applicable (else None)
        model     – 'grammarly/coedit-large', 'llama3.1:8b‑instruct', etc.
        prompt    – Full prompt sent to the model
        response  – Text returned by the model
    """
    entry = {
        "section": section,
        "field_id": field_id,
        "model": model,
        "prompt": prompt[:max_chars],
        "response": response[:max_chars],
        "timestamp": time.strftime("%Y‑%m‑%d %H:%M:%S"),
    }

    try:
        with open(LOG_FILE, "r") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(entry)

    with open(LOG_FILE, "w") as fh:
        json.dump(data, fh, indent=4)

    print(f"Logged LLM interaction for section '{section}', field {field_id}.")
# ------------------------------------------------------------------------------------------


def load_template_execsummary(path: str) -> list[dict]:
    """
    Reads a YAML or JSON executive‑summary template file and returns
    it as a list of section‑definition dictionaries.

    Raises FileNotFoundError if the file is missing and ValueError
    for unsupported extensions.
    """
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix.lower() in (".yml", ".yaml"):
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or []
    elif path.suffix.lower() == ".json":
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    else:
        raise ValueError("Template must be .yml/.yaml or .json")


def usage():
    """Prints usage instructions for the PlexTrac CLI Tool."""
    print("""
    Usage: python your_script.py --server-fqdn <FQDN> --client-name <CLIENT> --report-name <REPORT> [options]

    Required arguments:
      --server-fqdn     The Fully Qualified Domain Name (FQDN) of the PlexTrac server.
      --client-name     The name of the client in PlexTrac.
      --report-name     The name of the report to process.

    Optional arguments:
      --use-llama       Enable Llama for text processing.
      --use-grammarly   Enable Grammarly for text processing.
      --tgi-server-url  TGI Server URL for Grammarly (default: None) - TGI Server usually listens on 8080
      --ollama-server-url   Ollama server URL (default: None)  - Ollama usually listens on 11434

    Example usage:
      python peer_review_helper.py --server-fqdn example.com --client-name Acme --report-name SecurityAudit --use-llama --ollama-remote-url http://127.0.0.1:11434
    """)
    

def initialize():
    parser = argparse.ArgumentParser(description="PlexTrac CLI Tool", usage=usage.__doc__)
    parser.add_argument("--server-fqdn", required=True, help="PlexTrac server FQDN")
    parser.add_argument("--client-name", required=True, help="Client name")
    parser.add_argument("--report-name", required=True, help="Report name")
    parser.add_argument("--use-llama", action="store_true", help="Enable Llama for text processing (disabled by default)") 
    parser.add_argument("--use-grammarly", action="store_true", help="Enable Grammarly for text processing (disabled by default)")
    parser.add_argument("--tgi-server-url", default=None, help="TGI Server URL for Grammarly (default: None) - TGI Server usually listens on 8080")
    parser.add_argument("--ollama-remote-url", default=None, help="Ollama server URL (default: None) - Ollama usually listens on 11434")
    parser.add_argument("--use-html-aware-editing", action="store_true", help="Preserve and reinsert inline HTML tags when editing (default: disabled)")

    args = parser.parse_args()

    # Prompt for username and password
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    # Initialize API client
    api = PlexTracAPI(args.server_fqdn, username, password, ollama_remote_url=args.ollama_remote_url, tgi_remote_url=args.tgi_server_url, 
                      use_llama=args.use_llama, use_grammarly=args.use_grammarly, use_html_wrapping=args.use_html_aware_editing)
    api.authenticate()
    return args, api

def soft_format_html_for_terminal(text):
    """
    Adds basic newlines/indents for CLI readability while preserving all HTML tags.
    Does NOT strip or decode any tags — only adds line breaks and minimal formatting.
    """
    # Block-level tags → insert newlines before and/or after
    text = re.sub(r'</?(p|div|section|h[1-6]|br)[^>]*>', r'\n', text, flags=re.IGNORECASE)

    # List tags → format like bullets
    text = re.sub(r'<ul[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</ul>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<ol[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</ol>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<li[^>]*>', '\n  - ', text, flags=re.IGNORECASE)
    text = re.sub(r'</li>', '', text, flags=re.IGNORECASE)

    # Blockquotes → prefix with >
    text = re.sub(r'<blockquote[^>]*>', '\n> ', text, flags=re.IGNORECASE)
    text = re.sub(r'</blockquote>', '\n', text, flags=re.IGNORECASE)

    # Add line spacing around code blocks
    text = re.sub(r'<pre[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</pre>', '\n', text, flags=re.IGNORECASE)

    # Normalize line breaks (no more than 2 in a row)
    text = re.sub(r'\n\s*\n+', '\n\n', text)

    return text.strip()


def test_prompt_on_finding(api, finding_index, section_index, prompt, use_llama=True, use_grammarly=False):
    """
    Quickly test a custom prompt on a single section of a finding.
    Shows both raw LLM output and output using tag-safe editing via extractonlytext_sendtollm().
    """
    if not api.report_findings_content:
        print("No findings loaded. Run api.get_report_findings_content() first.")
        return

    if finding_index >= len(api.report_findings_content):
        print("Invalid finding index.")
        return

    finding = api.report_findings_content[finding_index]
    section_map = {
        0: ("title", finding.get("title", "")),
        1: ("description", finding.get("description", "")),
        2: ("recommendations", finding.get("recommendations", "")),
        3: ("guidance", finding.get("fields", {}).get("guidance", {}).get("value", "")),
        4: ("reproduction_steps", finding.get("fields", {}).get("reproduction_steps", {}).get("value", "")),
    }

    section_key, original_text = section_map.get(section_index, (None, None))
    if section_key is None:
        print("Invalid section index.")
        return

    print(f"\n=== Testing {section_key.upper()} on Finding #{finding_index} ===\n")

    # 1. ORIGINAL
    print("----- ORIGINAL TEXT -----")
    print(soft_format_html_for_terminal(original_text))

    # 2. BASIC LLM EDIT
    fixed = api.copy_editor.get_edits(
        original_text,
        use_llama=use_llama,
        use_grammarly=use_grammarly,
        prompts={"llama": prompt, "grammarly": prompt}
    )
    joined_fixed = "".join(fixed)

    print("\n----- LLM OUTPUT (plain text edit only) -----")
    print(soft_format_html_for_terminal(joined_fixed))

    # 3. HTML-PRESERVING EDIT (EXTRACT + REINSERT)
    def _wrapped_edit_func(text_chunk: str) -> str:
        result = api.copy_editor.get_edits(
            text_chunk,
            use_llama=use_llama,
            use_grammarly=use_grammarly,
            prompts={"llama": prompt, "grammarly": prompt}
        )
        return "".join(result)

    fully_wrapped = extractonlytext_sendtollm(original_text, _wrapped_edit_func)

    print("\n----- LLM OUTPUT (with inline HTML handling) -----")
    print(soft_format_html_for_terminal(fully_wrapped))


if __name__ == "__main__":
    args,api=initialize()

    # Backup report first
    if os.path.exists(args.client_name+"_"+args.report_name+'.ptrac') or os.path.exists(args.client_name+"_"+args.report_name+'.docx'):
        print (f"Report already exists and refusing to overwrite: {args.report_name}")
        sys.exit(0)

    exported=api.export_report(args.client_name, args.report_name)
    if exported is False:
        print ("Error exporting reports...quitting")
        sys.exit(0)
    
    # Get original report and display in an curses interface
    api.get_report_findings_content(args.client_name, args.report_name)
    exec_summary=api.get_local_exec_summary()
    findings=api.get_local_findings()
    all_text = exec_summary + findings
    paginated_text=generate_paginated_text(all_text)
    curses.wrapper(interactive_text_viewer, paginated_text)
