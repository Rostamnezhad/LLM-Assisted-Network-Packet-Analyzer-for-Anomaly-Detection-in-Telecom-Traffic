import streamlit as st

with open('C:\\Users\\soroush\\llm-packet-analyzer\\results\\analysis_output.txt', 'r', encoding='utf-8') as f:
    content = f.read()

st.title("LLM-Based Packet Analysis")
st.text_area("Analysis Output", content, height=500)
