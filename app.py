
import streamlit as st
import pandas as pd
from pathlib import Path

# --------------------------------------------------
# Page Configuration
# --------------------------------------------------

st.set_page_config(
    page_title="CyberIntel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# Dashboard Header
# --------------------------------------------------

st.title("🛡️ CyberIntel")
st.subheader("Cybersecurity Threat Intelligence Dashboard")

st.write(
    "Analyze known security vulnerabilities, explore estimated "
    "risk levels, and identify vulnerabilities associated with ransomware."
)

st.divider()

# --------------------------------------------------
# Load Data
# --------------------------------------------------

DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error(
        "Risk data not found. Please ensure that "
        "'outputs/risk_scored_vulnerabilities.csv' exists."
    )
    st.stop()

@st.cache_data
def load_data(file_path):
    data = pd.read_csv(file_path)

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
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {', '.join(missing_columns)}"
        )

    data["risk_score"] = pd.to_numeric(
        data["risk_score"], errors="coerce"
    )

    data["ransomware"] = pd.to_numeric(
        data["ransomware"], errors="coerce"
    )

    data["risk_tier"] = data["risk_tier"].fillna("Unknown")

    return data


try:
    df = load_data(str(DATA_FILE))
except (ValueError, OSError, pd.errors.ParserError) as error:
    st.error(f"Unable to load vulnerability data: {error}")
    st.stop()

# --------------------------------------------------
# Key Metrics
# --------------------------------------------------

total = len(df)

critical = (df["risk_tier"] == "Critical").sum()
high = (df["risk_tier"] == "High").sum()
medium = (df["risk_tier"] == "Medium").sum()
low = (df["risk_tier"] == "Low").sum()

ransomware_count = (df["ransomware"] == 1).sum()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Vulnerabilities", f"{total:,}")
col2.metric("Critical Risk", f"{critical:,}")
col3.metric("High Risk", f"{high:,}")
col4.metric("Ransomware-Related", f"{ransomware_count:,}")

st.divider()

# --------------------------------------------------
# Risk Distribution
# --------------------------------------------------

left, right = st.columns(2)

with left:
    st.subheader("Vulnerabilities by Risk Level")

    risk_order = ["Critical", "High", "Medium", "Low", "Unknown"]

    risk_counts = (
        df["risk_tier"]
        .value_counts()
        .reindex(risk_order, fill_value=0)
    )

    st.bar_chart(risk_counts)

with right:
    st.subheader("Top 10 Highest-Risk Vulnerabilities")

    top10 = (
        df.dropna(subset=["risk_score"])
        .nlargest(10, "risk_score")
    )

    if not top10.empty:
        chart_data = top10.set_index("cveID")["risk_score"]
        st.bar_chart(chart_data)
    else:
        st.info("No valid risk scores are available.")

# --------------------------------------------------
# Additional Statistics
# --------------------------------------------------

st.divider()
st.subheader("Threat Intelligence Overview")

col1, col2, col3 = st.columns(3)

col1.metric("Vendors", f"{df['vendorProject'].nunique():,}")
col2.metric("Products", f"{df['product'].nunique():,}")
col3.metric("Medium-Risk Vulnerabilities", f"{medium:,}")

st.caption(f"Low-risk vulnerabilities: {low:,}")

# --------------------------------------------------
# Search and Filter
# --------------------------------------------------

st.divider()
st.subheader("Search and Filter Vulnerabilities")

vendors = sorted(
    df["vendorProject"].dropna().astype(str).unique().tolist()
)

col1, col2 = st.columns(2)

with col1:
    selected_vendor = st.selectbox(
        "Filter by vendor",
        ["All Vendors"] + vendors
    )

with col2:
    risk_levels = ["Critical", "High", "Medium", "Low", "Unknown"]

    selected_risk = st.selectbox(
        "Filter by risk level",
        ["All Risk Levels"] + risk_levels
    )

search = st.text_input(
    "Search by CVE ID, vendor, or product",
    placeholder="Example: CVE-2024 or Microsoft"
)

filtered = df.copy()

if selected_vendor != "All Vendors":
    filtered = filtered[
        filtered["vendorProject"].astype(str) == selected_vendor
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

st.write(f"Showing **{len(filtered):,}** vulnerabilities")

display_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

filtered_display = (
    filtered[display_columns]
    .sort_values("risk_score", ascending=False, na_position="last")
)

st.dataframe(
    filtered_display,
    width="stretch",
    hide_index=True
)

# --------------------------------------------------
# Download Results
# --------------------------------------------------

csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="📥 Download Filtered Results",
    data=csv_data,
    file_name="cyberintel_filtered_results.csv",
    mime="text/csv"
)

# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "CyberIntel | Cybersecurity Threat Intelligence Dashboard"
)

st.caption(
    "Risk scores are model-generated estimates, not guarantees "
    "of future attacks. Validate findings against authoritative "
    "vulnerability advisories before making security decisions."
)
