# main.py
import datetime
import os
import subprocess
from typing import List, Dict, Optional
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
import logging
import json

# Setup logging
logging.basicConfig(level=logging.INFO, filename='security.log')
logger = logging.getLogger(__name__)

# Ensure logs directory exists
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Define state model
class SecurityState(BaseModel):
    task_list: List[Dict] = []
    executed_tasks: List[Dict] = []
    scope: List[str] = []
    scope_violations: List[str] = []
    current_task: Optional[Dict] = None
    retries: int = 0
    max_retries: int = 3

# Scope enforcement
def is_within_scope(target: str, scope: List[str]) -> bool:
    """Check if target is within defined scope."""
    for scope_item in scope:
        if scope_item in target or target in scope_item:
            return True
    return False

# Task execution (real tools for Windows)
def execute_security_tool(task: Dict, scope: List[str]) -> Dict:
    """Execute security tool with scope enforcement."""
    command = task["command"]
    tool = task["tool"]
    target = task["target"]
    
    if not is_within_scope(target, scope):
        violation_msg = f"Out-of-scope command attempted: {command}"
        return {
            "tool": tool,
            "command": command,
            "status": "failed",
            "error": violation_msg,
            "timestamp": str(datetime.datetime.now())
        }
    
    try:
        # On Windows, use shell=True for compatibility with command-line tools
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        return {
            "tool": tool,
            "command": command,
            "status": "success" if result.returncode == 0 else "failed",
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "timestamp": str(datetime.datetime.now())
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": tool,
            "command": command,
            "status": "failed",
            "error": "Command timed out after 300 seconds",
            "timestamp": str(datetime.datetime.now())
        }
    except Exception as e:
        return {
            "tool": tool,
            "command": command,
            "status": "failed",
            "error": str(e),
            "timestamp": str(datetime.datetime.now())
        }

# Report generation
def generate_audit_reports(state: SecurityState):
    """Generate JSON and Markdown audit reports."""
    audit_report = {
        "timestamp": str(datetime.datetime.now()),
        "target_scope": state.scope,
        "executed_tasks": state.executed_tasks,
        "scope_violations": state.scope_violations
    }
    
    json_path = os.path.join(LOGS_DIR, "audit_report.json")
    with open(json_path, "w") as f:
        json.dump(audit_report, f, indent=2)
    
    md_path = os.path.join(LOGS_DIR, "audit_report.md")
    with open(md_path, "w") as f:
        f.write("# Cybersecurity Audit Report\n\n")
        f.write(f"**Generated:** {audit_report['timestamp']}\n")
        f.write(f"**Target Scope:** {', '.join(state.scope)}\n\n")
        
        f.write("## Executed Tasks\n")
        for task in state.executed_tasks:
            f.write(f"### {task['tool']} Scan\n")
            f.write(f"- **Command:** `{task['command']}`\n")
            f.write(f"- **Status:** {task['status']}\n")
            f.write(f"- **Timestamp:** {task['timestamp']}\n")
            if task.get("output"):
                f.write(f"- **Output:**\n```\n{task['output'][:500]}...\n```\n")
            if task.get("error"):
                f.write(f"- **Error:** {task['error']}\n")
            f.write("\n")
        
        if state.scope_violations:
            f.write("## Scope Violations\n")
            for violation in state.scope_violations:
                f.write(f"- {violation}\n")
    
    logger.info(f"Audit reports generated: {json_path}, {md_path}")

# Task planning node
def plan_tasks(state: SecurityState) -> SecurityState:
    """Generate initial task list from instruction."""
    instruction = state.task_list[0]["instruction"] if state.task_list else ""
    
    if "scan" in instruction.lower() and "ports" in instruction.lower():
        state.task_list = [
            {
                "tool": "nmap",
                "command": f"nmap -p 1-1000 {state.scope[0]}",
                "target": state.scope[0],
                "status": "pending"
            }
        ]
    if "directories" in instruction.lower():
        state.task_list.append({
            "tool": "gobuster",
            "command": f"gobuster dir -u http://{state.scope[0]} -w common.txt",
            "target": state.scope[0],
            "status": "pending"
        })
    
    state.current_task = state.task_list[0]
    return state

# Task execution node
def execute_task(state: SecurityState) -> SecurityState:
    """Execute current task and update state."""
    if not state.current_task:
        return state
    
    result = execute_security_tool(state.current_task, state.scope)
    state.executed_tasks.append(result)
    
    if "Out-of-scope" in result.get("error", ""):
        state.scope_violations.append(result["error"])
    
    state.task_list = [t for t in state.task_list if t["status"] == "pending"]
    state.current_task = state.task_list[0] if state.task_list else None
    return state

# Analysis and task update node
def analyze_and_update(state: SecurityState) -> SecurityState:
    """Analyze results and update task list."""
    last_result = state.executed_tasks[-1] if state.executed_tasks else {}
    
    if last_result.get("tool") == "nmap" and last_result.get("status") == "success":
        if "80" in last_result.get("output", "") or "443" in last_result.get("output", ""):
            state.task_list.append({
                "tool": "gobuster",
                "command": f"gobuster dir -u http://{state.scope[0]} -w common.txt",
                "target": state.scope[0],
                "status": "pending"
            })
    
    return state

# Failure handling node
def handle_failure(state: SecurityState) -> str:
    """Handle task failures with retry logic."""
    last_result = state.executed_tasks[-1] if state.executed_tasks else {}
    
    if last_result.get("status") == "failed" and state.retries < state.max_retries:
        state.retries += 1
        logger.info(f"Retrying task {state.current_task['command']} (Attempt {state.retries})")
        return "execute"
    return "continue"

# Build the workflow
workflow = StateGraph(SecurityState)
workflow.add_node("plan", plan_tasks)
workflow.add_node("execute", execute_task)
workflow.add_node("analyze", analyze_and_update)
workflow.set_entry_point("plan")
workflow.add_edge("plan", "execute")
workflow.add_edge("execute", "analyze")
workflow.add_conditional_edges(
    "analyze",
    handle_failure,
    {"execute": "execute", "continue": END}
)

# Compile and run
app = workflow.compile()

def run_security_scan(instruction: str, scope: List[str]):
    """Run the security workflow and generate audit report."""
    initial_state = SecurityState(
        task_list=[{"instruction": instruction}],
        scope=scope
    )
    
    result = app.invoke(initial_state)
    generate_audit_reports(result)
    return result

if __name__ == "__main__":
    scope = ["example.com"]
    result = run_security_scan(
        "Scan example.com for open ports and discover directories",
        scope
    )
    print(f"Completed with {len(result.executed_tasks)} tasks executed")