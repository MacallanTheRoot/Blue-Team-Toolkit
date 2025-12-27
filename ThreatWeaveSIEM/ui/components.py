"""Reusable Streamlit UI components."""
import streamlit as st
import pandas as pd

def metric_card(title: str, value, help_text: str | None = None):
    st.metric(title, value)
    if help_text:
        st.caption(help_text)

def table(df: pd.DataFrame, use_index: bool = False):
    st.dataframe(df, use_container_width=True)
