
import streamlit as st
import pandas as pd
from pathlib import Path

# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="CyberIntel | Threat Analysis",
    page_icon="🔐",
    layout="wide"
)

# ---------------- HEADER ----------------
st.title("🔐 CyberIntel Threat Monitor")
st.markdown(
    "Explore cybersecurity vulnerabilities, assess estimated risk, "
    "and identify ransomware-related threats."
)

st.caption("Cybersecurity Threat Intelligence Platform")
st.divider()

# ---------------- LOAD DATA ----------------
DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error(
        "Risk data file not found. Please ensure "
        "'outputs/risk_scored_vulnerabilities.csv' exists."
    )
    st.stop()

df = pd.read_csv(DATA_FILE)

# Validate required columns
required_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

missing_columns = [
    column for column in required_columns
    if column not in df.columns
]

if missing_columns:
    st.error(f"Missing required columns: {', '.join(missing_columns)}")
    st.stop()

# Clean data
df["risk_score"] = pd.to_numeric(
    df["risk_score"], errors="coerce"
)
df["ransomware"] = pd.to_numeric(
    df["ransomware"], errors="coerce"
)

df["risk_tier"] = df["risk_tier"].fillna("Unknown")
df["cveID"] = df["cveID"].fillna("")
df["vendorProject"] = df["vendorProject"].fillna("")
df["product"] = df["product"].fillna("")

# ---------------- SUMMARY METRICS ----------------
total_vulnerabilities = len(df)
critical_count = (df["risk_tier"] == "Critical").sum()
high_count = (df["risk_tier"] == "High").sum()
ransomware_count = (df["ransomware"] == 1).sum()

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Vulnerabilities",
    f"{total_vulnerabilities:,}"
)

col2.metric(
    "Critical Threats",
    f"{critical_count:,}"
)

col3.metric(
    "High-Risk Threats",
    f"{high_count:,}"
)

col4.metric(
    "Ransomware Cases",
    f"{ransomware_count:,}"
)

st.divider()

# ---------------- CHARTS ----------------
st.subheader("Threat Intelligence Analytics")

chart_left, chart_right = st.columns(2)

with chart_left:
    st.markdown("#### Risk Distribution")

    risk_order = ["Critical", "High", "Medium", "Low", "Unknown"]

    risk_counts = (
        df["risk_tier"]
        .value_counts()
        .reindex(risk_order, fill_value=0)
    )

    st.bar_chart(risk_counts)

with chart_right:
    st.markdown("#### Highest-Risk CVEs")

    top_vulnerabilities = (
        df.dropna(subset=["risk_score"])
        .nlargest(10, "risk_score")
        .copy()
    )

    if not top_vulnerabilities.empty:
        chart_data = top_vulnerabilities.set_index("cveID")[
            ["risk_score"]
        ]
        st.bar_chart(chart_data)
    else:
        st.info("No valid risk scores are available.")

st.divider()

# ---------------- FILTERS AND SEARCH ----------------
st.subheader("🔎 Vulnerability Explorer")

filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    vendor_options = sorted(
        df.loc[df["vendorProject"] != "", "vendorProject"].unique()
    )

    vendor_choice = st.selectbox(
        "Select vendor",
        ["All Vendors"] + vendor_options
    )

with filter_col2:
    available_risks = sorted(
        df["risk_tier"].unique(),
        key=lambda value: (
            ["Critical", "High", "Medium", "Low", "Unknown"]
            .index(value)
            if value in ["Critical", "High", "Medium", "Low", "Unknown"]
            else 99
        )
    )

    risk_choice = st.selectbox(
        "Select risk category",
        ["All Categories"] + available_risks
    )

search_query = st.text_input(
    "Search CVE ID, vendor, or product",
    placeholder="Example: CVE-2025 or Microsoft"
)

# ---------------- APPLY FILTERS ----------------
results = df.copy()

if vendor_choice != "All Vendors":
    results = results[
        results["vendorProject"] == vendor_choice
    ]

if risk_choice != "All Categories":
    results = results[
        results["risk_tier"] == risk_choice
    ]

if search_query.strip():
    query = search_query.strip()

    search_mask = (
        results["cveID"].str.contains(
            query, case=False, regex=False
        )
        | results["vendorProject"].str.contains(
            query, case=False, regex=False
        )
        | results["product"].str.contains(
            query, case=False, regex=False
        )
    )

    results = results[search_mask]

results = results.sort_values(
    "risk_score",
    ascending=False,
    na_position="last"
)

# ---------------- RESULTS TABLE ----------------
st.markdown("#### Vulnerability Records")
st.write(f"Matching records: **{len(results):,}**")

display_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

st.dataframe(
    results[display_columns],
    use_container_width=True,
    hide_index=True
)

# ---------------- DOWNLOAD ----------------
csv_data = results.to_csv(index=False).encode("utf-8")

st.download_button(
    label="📥 Export Search Results",
    data=csv_data,
    file_name="cyberintel_vulnerability_report.csv",
    mime="text/csv"
)

# ---------------- FOOTER ----------------
st.divider()

st.caption(
    "CyberIntel | Academic Cybersecurity Analytics Project"
)

st.caption(
    "Risk scores are model-generated estimates for analysis. "
    "They do not guarantee that a vulnerability will be exploited."
)
