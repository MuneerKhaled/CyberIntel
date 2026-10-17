
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
    "Analyze known security vulnerabilities "
    "and explore their estimated risk."
)

DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error("Risk data not found. Check the outputs folder.")
    st.stop()

df = pd.read_csv(DATA_FILE)

required_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

missing_columns = [
    col for col in required_columns if col not in df.columns
]

if missing_columns:
    st.error(f"Missing required columns: {missing_columns}")
    st.stop()

df["risk_score"] = pd.to_numeric(
    df["risk_score"], errors="coerce"
)
df["ransomware"] = pd.to_numeric(
    df["ransomware"], errors="coerce"
)

df["risk_tier"] = df["risk_tier"].fillna("Unknown")

total = len(df)
critical = (df["risk_tier"] == "Critical").sum()
high = (df["risk_tier"] == "High").sum()
ransomware_count = (df["ransomware"] == 1).sum()

a, b, c, d = st.columns(4)

a.metric("Total Vulnerabilities", f"{total:,}")
b.metric("Critical Risk", f"{critical:,}")
c.metric("High Risk", f"{high:,}")
d.metric("Ransomware-Related", f"{ransomware_count:,}")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Vulnerabilities by Risk Level")
    risk_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    counts = df["risk_tier"].value_counts()
    counts = counts.reindex(
        [risk for risk in risk_order if risk in counts.index]
    )
    st.bar_chart(counts)

with right:
    st.subheader("Top 10 Highest-Risk Vulnerabilities")
    top10 = df.nlargest(10, "risk_score").dropna(
        subset=["risk_score"]
    )

    if not top10.empty:
        chart_data = top10.set_index("cveID")["risk_score"]
        st.bar_chart(chart_data)
    else:
        st.info("No valid risk scores available.")

st.divider()

st.subheader("Search and Filter Vulnerabilities")

vendors = sorted(
    df["vendorProject"].dropna().astype(str).unique()
)

selected_vendor = st.selectbox(
    "Filter by vendor",
    ["All Vendors"] + vendors
)

risk_levels = ["Critical", "High", "Medium", "Low", "Unknown"]

selected_risk = st.selectbox(
    "Filter by risk level",
    ["All Risk Levels"] + risk_levels
)

search = st.text_input(
    "Search by CVE ID, vendor, or product"
)

filtered = df.copy()

if selected_vendor != "All Vendors":
    filtered = filtered[
        filtered["vendorProject"] == selected_vendor
    ]

if selected_risk != "All Risk Levels":
    filtered = filtered[
        filtered["risk_tier"] == selected_risk
    ]

if search.strip():
    search = search.strip()

    mask = (
        filtered["cveID"].fillna("").astype(str).str.contains(
            search, case=False, regex=False
        )
        | filtered["vendorProject"].fillna("").astype(str).str.contains(
            search, case=False, regex=False
        )
        | filtered["product"].fillna("").astype(str).str.contains(
            search, case=False, regex=False
        )
    )

    filtered = filtered[mask]

st.write(f"Showing {len(filtered):,} vulnerabilities")

display_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

st.dataframe(
    filtered[display_columns].sort_values(
        "risk_score",
        ascending=False,
        na_position="last"
    ),
    width="stretch",
    hide_index=True
)

st.download_button(
    label="Download Filtered Results",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="cyberintel_filtered_results.csv",
    mime="text/csv"
)

st.divider()

st.caption(
    "Risk scores are model-generated estimates, "
    "not guarantees of future attacks."
)
