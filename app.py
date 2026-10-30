
import streamlit as st
import pandas as pd
from pathlib import Path

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CyberIntel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ CyberIntel")
st.subheader("Cybersecurity Threat Intelligence Dashboard")

st.write(
    "Analyze known security vulnerabilities, explore their estimated "
    "risk levels, and identify vulnerabilities associated with ransomware."
)

st.divider()

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error(
        "Risk data not found. Please ensure that "
        "'outputs/risk_scored_vulnerabilities.csv' exists."
    )
    st.stop()

try:
    df = pd.read_csv(DATA_FILE)
except Exception as error:
    st.error(f"Failed to load vulnerability data: {error}")
    st.stop()

# --------------------------------------------------
# VALIDATE REQUIRED COLUMNS
# --------------------------------------------------

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
    st.error(
        f"Missing required columns in the dataset: "
        f"{', '.join(missing_columns)}"
    )
    st.stop()

if df.empty:
    st.warning("The vulnerability dataset is empty.")
    st.stop()

# --------------------------------------------------
# CLEAN DATA
# --------------------------------------------------

df["risk_score"] = pd.to_numeric(
    df["risk_score"],
    errors="coerce"
)

df["ransomware"] = pd.to_numeric(
    df["ransomware"],
    errors="coerce"
)

df["risk_tier"] = df["risk_tier"].astype("string").str.strip()

for column in ["cveID", "vendorProject", "product"]:
    df[column] = df[column].astype("string")

# --------------------------------------------------
# KEY PERFORMANCE INDICATORS
# --------------------------------------------------

total = len(df)

critical = (df["risk_tier"] == "Critical").sum()

high = (df["risk_tier"] == "High").sum()

medium = (df["risk_tier"] == "Medium").sum()

low = (df["risk_tier"] == "Low").sum()

ransomware_count = (df["ransomware"] == 1).sum()

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    label="Total Vulnerabilities",
    value=f"{total:,}"
)

col2.metric(
    label="Critical Risk",
    value=f"{critical:,}"
)

col3.metric(
    label="High Risk",
    value=f"{high:,}"
)

col4.metric(
    label="Ransomware-Related",
    value=f"{ransomware_count:,}"
)

st.divider()

# --------------------------------------------------
# RISK DISTRIBUTION AND TOP VULNERABILITIES
# --------------------------------------------------

left, right = st.columns(2)

with left:
    st.subheader("📊 Vulnerabilities by Risk Level")

    risk_order = ["Critical", "High", "Medium", "Low"]

    risk_counts = (
        df["risk_tier"]
        .value_counts()
        .reindex(risk_order, fill_value=0)
    )

    st.bar_chart(risk_counts)

    st.caption(
        "Distribution of vulnerabilities across the four risk levels."
    )

with right:
    st.subheader("⚠️ Top 10 Highest-Risk Vulnerabilities")

    top10 = (
        df.dropna(subset=["risk_score"])
        .nlargest(10, "risk_score")
    )

    if not top10.empty:
        chart_data = top10.set_index("cveID")["risk_score"]

        st.bar_chart(chart_data)

    else:
        st.info("No valid risk scores are available.")

    st.caption(
        "Vulnerabilities ranked by their model-generated risk scores."
    )

st.divider()

# --------------------------------------------------
# ADDITIONAL STATISTICS
# --------------------------------------------------

st.subheader("📈 Dataset Overview")

stat1, stat2, stat3 = st.columns(3)

stat1.metric(
    "Medium-Risk Vulnerabilities",
    f"{medium:,}"
)

stat2.metric(
    "Low-Risk Vulnerabilities",
    f"{low:,}"
)

vendor_count = df["vendorProject"].nunique()

stat3.metric(
    "Unique Vendors",
    f"{vendor_count:,}"
)

st.divider()

# --------------------------------------------------
# SEARCH AND FILTER
# --------------------------------------------------

st.subheader("🔎 Search and Filter Vulnerabilities")

filter_col1, filter_col2 = st.columns(2)

vendors = sorted(
    df["vendorProject"].dropna().unique().tolist(),
    key=str.casefold
)

with filter_col1:
    selected_vendor = st.selectbox(
        "Filter by vendor",
        ["All Vendors"] + vendors
    )

with filter_col2:
    risk_levels = ["Critical", "High", "Medium", "Low"]

    selected_risk = st.selectbox(
        "Filter by risk level",
        ["All Risk Levels"] + risk_levels
    )

search = st.text_input(
    "Search by CVE ID, vendor, or product",
    placeholder="Example: CVE-2024, Microsoft, or Windows"
)

# --------------------------------------------------
# APPLY FILTERS
# --------------------------------------------------

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
    search_term = search.strip()

    search_mask = (
        filtered["cveID"]
        .fillna("")
        .str.contains(search_term, case=False, regex=False)
        |
        filtered["vendorProject"]
        .fillna("")
        .str.contains(search_term, case=False, regex=False)
        |
        filtered["product"]
        .fillna("")
        .str.contains(search_term, case=False, regex=False)
    )

    filtered = filtered[search_mask]

# --------------------------------------------------
# DISPLAY FILTERED RESULTS
# --------------------------------------------------

st.write(f"**Showing {len(filtered):,} vulnerabilities**")

display_columns = [
    "cveID",
    "vendorProject",
    "product",
    "risk_score",
    "risk_tier",
    "ransomware"
]

display_df = (
    filtered[display_columns]
    .sort_values(
        "risk_score",
        ascending=False,
        na_position="last"
    )
)

st.dataframe(
    display_df,
    width="stretch",
    hide_index=True
)

# --------------------------------------------------
# DOWNLOAD FILTERED RESULTS
# --------------------------------------------------

csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="📥 Download Filtered Results",
    data=csv_data,
    file_name="cyberintel_filtered_results.csv",
    mime="text/csv"
)

st.divider()

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.caption(
    "🛡️ CyberIntel | Cybersecurity Threat Intelligence Dashboard"
)

st.caption(
    "Risk scores are model-generated estimates and do not guarantee "
    "that a vulnerability will be exploited. Risk classifications "
    "depend on the underlying dataset and scoring methodology."
)
