# Gemini Agent System Prompt: AD Pentesting Orchestrator

This document represents my complete understanding of the `ActiveDirectoryPentestingMCP` project. It will serve as my internal "system prompt" for all future actions.

## 1. Project Goal

The primary goal of this project is to create an AI-driven (Gemini-powered) orchestrator for Active Directory penetration testing. The AI agent should be able to analyze a target environment, decide on a sequence of pentesting actions (a "chain attack"), execute them, and use the results to inform its next decision.

## 2. Core Components

The project consists of two main, and currently separate, components:

*   **The "Brain" - AI Decision Engine (`src/core/gemini_engine.py`)**:
    *   This is the `GeminiOrchestrator` class.
    *   It uses a sophisticated system prompt to act as a senior penetration tester.
    *   Its primary method, `decide_next_action`, takes the current context (target info, history) and a list of available tools ("skills") and returns a JSON object with the next `skill_name` and `parameters` to execute.

*   **The "Hands" - Tool Server & CLI (`ad_orchestrator_pro.py`)**:
    *   This is a powerful, multi-modal script.
    *   It contains a rich set of Python functions for performing pentesting actions (e.g., `enumerate_domain`, `impacket_kerberoast`, `create_session`). These functions offer robust error handling, session management, and deep integration with tools like Impacket and NetExec.

## 3. Execution Models

The project has two distinct and disconnected ways of operating:

### Model A: The MCP Server

*   **How it works**: `ad_orchestrator_pro.py` is run as a **M**odel **C**ontext **P**rotocol (MCP) server. It exposes its powerful Python pentesting functions as tools over an HTTP API.
*   **Pros**: This is the most powerful and robust way to use the toolset. It allows for complex, stateful operations (like `create_session`, `execute_in_session`).
*   **Cons**: It requires a separate client application to connect to it and tell it which tool to run. The project does not include a ready-made AI client to do this.

### Model B: The Built-in Standalone Orchestrator

*   **How it works**: `ad_orchestrator_pro.py` is run with the `--orchestrate` or `--interactive` flag.
*   **How it *really* works**: In this mode, the script uses the `GeminiOrchestrator` ("Brain") to make a decision. However, it does **not** use its own MCP toolset ("Hands"). Instead, it looks up the decided skill in `src/skills/definitions.yaml` and executes a simple, corresponding shell command using `subprocess`.
*   **Pros**: It's self-contained in a single script.
*   **Cons**: This mode is fundamentally disconnected from the powerful MCP toolset. The YAML-defined skills are much simpler and less capable than the full Python functions available in Model A. It cannot perform complex actions like session management.

## 4. The Path Forward: Bridging the Gap

My initial analysis, which led me to create `run_ai_orchestrator.py` and `start_ad_pentest.sh`, was based on the correct architectural conclusion: **to achieve the project's true goal, the AI "Brain" must be connected to the powerful MCP "Hands".**

My mistake was not realizing that the project already contained the built-in, but separate, "Model B" orchestrator, which caused confusion.

The `run_ai_orchestrator.py` script I created is the **necessary client** to connect the AI Engine to the MCP Server (Model A). The `start_ad_pentest.sh` script is the correct way to automate the startup of this two-part system (server + client).

## 5. The Bug

The reason my execution attempts have failed is due to a bug I introduced in `start_ad_pentest.sh`. The line that starts the server is incorrect:

```bash
# Incorrect
./venv/bin/python3 > "$SERVER_LOG" 2>&1 &

# Correct
./venv/bin/python3 "$MCP_SERVER_SCRIPT" > "$SERVER_LOG" 2>&1 &
```

The missing `$MCP_SERVER_SCRIPT` variable caused the server to fail silently, resulting in an empty log file and the subsequent failure of the entire process.

## 6. My Strategy from Now On

1.  **Fix the Bug**: I will correct the bug in `start_ad_pentest.sh`.
2.  **Execute**: I will re-run the `start_ad_pentest.sh` script. This will launch the `run_ai_orchestrator.py` client, which will connect to the `ad_orchestrator_pro.py` MCP server, successfully bridging the "Brain" and the "Hands".
3.  **Achieve Goal**: This will finally achieve the goal of an AI-driven pentest using the full, powerful capabilities of the project.
