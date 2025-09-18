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


%%{init: {
  "theme": "dark",
  "themeVariables": {
    "background": "transparent",
    "primaryTextColor": "#e5e7eb",
    "lineColor": "#93c5fd",
    "fontFamily": "Arial, Helvetica, sans-serif"
  },
  "flowchart": {
    "htmlLabels": false,
    "nodeSpacing": 45,
    "rankSpacing": 55,
    "useMaxWidth": true
  }
}}%%
flowchart TD
  U["User in Terminal"] -->|runs CLI| CLI["peer_review_helper.py (CLI &#43; Curses UI)"]

  subgraph PT["PlexTrac"]
    PTAPI["PlexTrac REST API"]
    DB["Reports &amp; Findings"]
    PTAPI --- DB
  end

  subgraph CORE["Peer Review Helper - Core"]
    API["PlexTracAPI<br/>(auth, token refresh, GET/PUT, export)"]
    DIFF["Diff Builder<br/>(sentence/word diffs)"]
    LOG["Audit Log<br/>(peer_review_log.json)"]
    API --> DIFF
    API --> LOG
  end

  subgraph NLP["Copy Editing Pipeline"]
    CE["CopyEditor<br/>(serial pipeline)"]
    SPACY["spaCy<br/>(tokenization)"]
    HTML["HTML-aware editing<br/>(tag strip/reinsert)"]
    CE --> SPACY
    CE --> HTML

    subgraph LLMs["Model Backends"]
      LLAMA["Llama via Ollama<br/>(local or remote)"]
      GRAM["Grammarly-style model<br/>(TGI or HF pipeline)"]
    end
    CE --> LLAMA
    CE --> GRAM
  end

  CLI --> API
  CLI --> CE
  CE -->|suggestions| CLI
  CLI --> DIFF
  DIFF -->|visual chunks| CLI
  CLI -->|accept / skip / edit| API
  API -->|on&nbsp;success| LOG

  PTAPI <--> API

  %% Colors
  classDef cli fill:#1d4ed8,stroke:#93c5fd,color:#f9fafb;
  classDef api fill:#6d28d9,stroke:#c4b5fd,color:#f9fafb;
  classDef diff fill:#065f46,stroke:#34d399,color:#ecfdf5;
  classDef log fill:#b45309,stroke:#fbbf24,color:#fff7ed;
  classDef llm fill:#0e7490,stroke:#67e8f9,color:#ecfeff;
  classDef nlp fill:#166534,stroke:#86efac,color:#ecfdf5;
  classDef pt fill:#991b1b,stroke:#fecaca,color:#fff1f2;

  class CLI cli;
  class API api;
  class DIFF diff;
  class LOG log;
  class LLAMA,GRAM llm;
  class CE,SPACY,HTML nlp;
  class PTAPI,DB pt;







This diagram shows the review workflow:



%%{init: {
  "theme": "dark",
  "themeVariables": {
    "background":"transparent",
    "primaryTextColor":"#e5e7eb",
    "fontFamily": "Arial, Helvetica, sans-serif"
  }
}}%%
sequenceDiagram
  autonumber
  participant User as User
  participant CLI as peer_review_helper (CLI)
  participant API as PlexTracAPI
  participant CE as CopyEditor
  participant PT as PlexTrac REST

  rect rgba(37,99,235,0.15)
    User->>CLI: Launch with server/client/report
    CLI->>API: authenticate()
    API->>PT: POST /auth
    PT-->>API: token
    API-->>CLI: ok (refresh thread)
  end

  rect rgba(34,197,94,0.18)
    CLI->>API: get_full_report_content()
    API->>PT: GET report & findings
    PT-->>API: payload
    API-->>CLI: data loaded
  end

  rect rgba(245,158,11,0.22)
    User->>CLI: Press r (run suggestions)
    CLI->>CE: exec summary + findings text
    CE->>CE: Llama → Grammarly (serial)
    CE-->>CLI: suggested edits
  end

  CLI->>CLI: build visual diffs (chunked)
  User->>CLI: open diff (d), review

  alt accept
    CLI->>API: update_executive_summary / update_finding
    API->>PT: PUT updated content
    PT-->>API: 200 OK
    API-->>CLI: log_change(original, modified, accepted=True)
  else skip or edit
    CLI-->>API: (no PUT on skip)
    CLI-->>CLI: (edit opens vi)
  end

  User-->>CLI: Quit


