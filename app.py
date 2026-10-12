
import streamlit as st
import pandas as pd
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="CyberIntel | Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Dashboard header
st.title("🛡️ CyberIntel Threat Monitor")
st.markdown(
    "A machine-learning dashboard for exploring cybersecurity "
    "vulnerabilities and their estimated risk levels."
)

st.divider()

# Load dataset
DATA_FILE = Path("outputs/risk_scored_vulnerabilities.csv")

if not DATA_FILE.exists():
    st.error("Dataset not found. Please check the outputs folder.")
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

missing = [col for col in required_columns if col not in df.columns]

if missing:
    st.error(f"Missing required columns: {', '.join(missing)}")
    st.stop()

# Clean data
df["risk_score"] = pd.to_numeric(
    df["risk_score"], errors="coerce"
)
df["ransomware"] = pd.to_numeric(
    df["ransomware"], errors="coerce"
)

df["risk_tier"] = df["risk_tier"].fillna("Unknown")
df["vendorProject"] = df["vendorProject"].fillna("Unknown")
df["product"] = df["product"].fillna("Unknown")
df["cveID"] = df["cveID"].fillna("Unknown")

# Calculate dashboard metrics
total = len(df)
critical = (df["risk_tier"] == "Critical").sum()
high = (df["risk_tier"] == "High").sum()
ransomware_count = (df["ransomware"] == 1).sum()

# Summary metrics
st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total CVEs", f"{total:,}")
col2.metric("Critical Vulnerabilities", f"{critical:,}")
col3.metric("High-Risk Vulnerabilities", f"{high:,}")
col4.metric("Ransomware-Related", f"{ransomware_count:,}")

st.divider()

# Visual analytics
st.subheader("Vulnerability Analytics")

left, right = st.columns(2)

with left:
    st.markdown("#### Risk Level Distribution")

    risk_counts = (
        df["risk_tier"]
        .value_counts()
        .reindex(["Critical", "High", "Medium", "Low", "Unknown"])
        .dropna()
    )

    st.bar_chart(risk_counts)

with right:
    st.markdown("#### Highest-Risk CVEs")

    top_vulnerabilities = (
        df.dropna(subset=["risk_score"])
        .nlargest(10, "risk_score")
        .set_index("cveID")[["risk_score"]]
    )

    st.bar_chart(top_vulnerabilities)

st.divider()

# Filtering section
st.subheader("Explore Vulnerabilities")

filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    vendors = sorted(df["vendorProject"].unique())

    selected_vendors = st.multiselect(
        "Select vendors",
        options=vendors,
        placeholder="All vendors"
    )

with filter_col2:
    available_risks = [
        level for level in ["Critical", "High", "Medium", "Low"]
        if level in df["risk_tier"].values
    ]

    selected_risks = st.multiselect(
        "Select risk levels",
        options=available_risks,
        placeholder="All risk levels"
    )

search_term = st.text_input(
    "Search CVE ID, vendor, or product",
    placeholder="Example: CVE-2024 or Microsoft"
)

ransomware_only = st.checkbox(
    "Show ransomware-related vulnerabilities only"
)

# Apply filters
filtered = df.copy()

if selected_vendors:
    filtered = filtered[
        filtered["vendorProject"].isin(selected_vendors)
    ]

if selected_risks:
    filtered = filtered[
        filtered["risk_tier"].isin(selected_risks)
    ]

if search_term:
    mask = (
        filtered["cveID"].str.contains(
            search_term, case=False, regex=False
        )
        | filtered["vendorProject"].str.contains(
            search_term, case=False, regex=False
        )
        | filtered["product"].str.contains(
            search_term, case=False, regex=False
        )
    )
    filtered = filtered[mask]

if ransomware_only:
    filtered = filtered[filtered["ransomware"] == 1]

# Results table
st.markdown("#### Search Results")

st.write(f"Found **{len(filtered):,}** matching vulnerabilities.")

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
    use_container_width=True,
    hide_index=True
)

# Download filtered data
csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="📥 Export Results to CSV",
    data=csv_data,
    file_name="cyberintel_vulnerabilities.csv",
    mime="text/csv"
)

st.divider()

st.caption(
    "CyberIntel uses machine-learning-generated risk estimates. "
    "These scores are not guarantees of future cyberattacks."
)
