# app.py
import streamlit as st
from main import run_security_scan, SecurityState
import os

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Streamlit UI
st.title("Agentic Cybersecurity Workflow")
st.write("Enter a security instruction and define the scope to run scans. Ensure nmap and gobuster are installed.")

# User inputs
instruction = st.text_input("Security Instruction", "Scan example.com for open ports and discover directories")
scope_input = st.text_input("Target Scope (comma-separated)", "example.com")
run_button = st.button("Run Scan")

# Process and display results
if run_button and instruction and scope_input:
    scope = [s.strip() for s in scope_input.split(",")]
    with st.spinner("Running security scans..."):
        result = run_security_scan(instruction, scope)
    
    st.success("Scan completed!")
    
    # Display executed tasks
    st.subheader("Executed Tasks")
    for task in result.executed_tasks:
        st.write(f"**Tool:** {task['tool']}")
        st.write(f"**Command:** `{task['command']}`")
        st.write(f"**Status:** {task['status']}")
        st.write(f"**Timestamp:** {task['timestamp']}")
        if task.get("output"):
            st.code(task["output"][:500] + "..." if len(task["output"]) > 500 else task["output"])
        if task.get("error"):
            st.error(f"Error: {task['error']}")
        st.write("---")
    
    # Display scope violations
    if result.scope_violations:
        st.subheader("Scope Violations")
        for violation in result.scope_violations:
            st.write(f"- {violation}")
    
    # Provide download links for reports
    json_path = "logs/audit_report.json"
    md_path = "logs/audit_report.md"
    if os.path.exists(json_path):
        with open(json_path, "r") as f:
            st.download_button("Download JSON Report", f.read(), "audit_report.json")
    if os.path.exists(md_path):
        with open(md_path, "r") as f:
            st.download_button("Download Markdown Report", f.read(), "audit_report.md")