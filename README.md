# Tool to assist with peer reviewing of pentest reports

- NLP based suggestions for report edits
- Thanks to Danny Nassre (nassre@gmail.com) for providing the LLM Integration

Todo's:
- Unit tests (In Progress)

# Requirements

- cli
- Plextrac account with api access
- if using llama, it expects ollama listening on 127.0.0.1:11434 - adjust as needed
- if using grammarly server should be listening on 127.0.0.0.1:8080 for the Text generation interface (TGI) server, or you can ignore the server specification and just load the model locally without a server
- Python version 3.10

# installation

- pip install -r requirements.txt
- python -m spacy download en_core_web_sm

# Usage

- Ollama server is needed to get llama3.X:instruct text suggestions (either available via http://127.0.0.1:11434 or a remote url)
- Grammarly model can be loaded locally without needing a running server.  It will use the hugging face pipeline to accomplish this.

<code>
PlexTrac CLI Tool

options:
  -h, --help            show this help message and exit
  --server-fqdn SERVER_FQDN PlexTrac server FQDN
  --client-name CLIENT_NAME Client name
  --report-name REPORT_NAME Report name
  --use-llama           Enable Llama for text processing (disabled by default)
  --use-grammarly       Enable Grammarly for text processing (disabled by default)
  --tgi-server-url TGI_SERVER_URL TGI Server URL for Grammarly (default: None) - TGI Server usually listens on 8080
  --ollama-remote-url OLLAMA_REMOTE_URL Ollama server URL (default: None) - Ollama usually listens on 11434
  --use-html-aware-editing Preserve and reinsert inline HTML tags when editing (default: disabled)

</code>

Running the script it performs the following first:

1. ensure plextrac server is reachable and we can authenticate

2. user provides the plextrac url, client name and report name. system ensures report exists and the requesting user has access to it.

At this point the report is downloaded and presented to the user in the cli menu.  The user can choose to have the llm generate suggestions:

3. parse executive summary and suggest nlp fixes.

4. repeat for each report findings, including title

5. give summary of changes and let a user reject, edit, or accept changes.  if changes are edited a vi window is opened in the terminal and once the user finishes editing and exits vi the changes are saved in plextrac.  Otherwise they can accept the change as is or reject it.



The below diagrams show the architecture of the tool and its review workflow:

[!Architecture](docs/architecture.svg)


[!Review Workflow](docs/review_workflow.svg)
