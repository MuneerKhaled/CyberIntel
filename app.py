import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="CyberIntel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberIntel")
st.subheader("Cybersecurity Threat Intelligence Dashboard")
st.write(
    "Analyze known security vulnerabilities and explore their estimated risk."
)

DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error("Risk data not found. Run the notebook first.")
    st.stop()

df = pd.read_csv(DATA_FILE)

df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")
df["ransomware"] = pd.to_numeric(df["ransomware"], errors="coerce")

total = len(df)
critical = (df["risk_tier"] == "Critical").sum()
high = (df["risk_tier"] == "High").sum()
ransomware = (df["ransomware"] == 1).sum()

a, b, c, d = st.columns(4)
a.metric("Total Vulnerabilities", total)
b.metric("Critical Risk", int(critical))
c.metric("High Risk", int(high))
d.metric("Ransomware-Related", int(ransomware))

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Vulnerabilities by Risk Level")
    counts = df["risk_tier"].value_counts()
    st.bar_chart(counts)

with right:
    st.subheader("Top 10 Highest-Risk Vulnerabilities")
    top10 = df.nlargest(10, "risk_score")
    st.bar_chart(top10.set_index("cveID")["risk_score"])

st.divider()

st.subheader("Search and Filter Vulnerabilities")

vendors = sorted(df["vendorProject"].dropna().unique())
selected_vendor = st.selectbox(
    "Filter by vendor",
    ["All Vendors"] + vendors
)

risk_levels = ["Critical", "High", "Medium", "Low"]
selected_risk = st.selectbox(
    "Filter by risk level",
    ["All Risk Levels"] + risk_levels
)

search = st.text_input("Search by CVE ID, vendor, or product")

filtered = df.copy()

if selected_vendor != "All Vendors":
    filtered = filtered[
        filtered["vendorProject"] == selected_vendor
    ]

if selected_risk != "All Risk Levels":
    filtered = filtered[
        filtered["risk_tier"] == selected_risk
    ]

if search:
    mask = (
        filtered["cveID"].fillna("").str.contains(search, case=False, regex=False)
        | filtered["vendorProject"].fillna("").str.contains(search, case=False, regex=False)
        | filtered["product"].fillna("").str.contains(search, case=False, regex=False)
    )
    filtered = filtered[mask]

st.write(f"Showing {len(filtered)} vulnerabilities")

st.dataframe(
    filtered[
        [
            "cveID",
            "vendorProject",
            "product",
            "risk_score",
            "risk_tier",
            "ransomware"
        ]
    ].sort_values("risk_score", ascending=False),
    width="stretch",
    hide_index=True
)

st.download_button(
    "Download Filtered Results",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="cyberintel_filtered_results.csv",
    mime="text/csv"
)

st.caption(
    "Risk scores are model-generated estimates, not guarantees of future attacks."
)

