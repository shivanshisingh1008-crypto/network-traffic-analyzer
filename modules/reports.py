from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def build_pdf_report(df, alerts, source_name):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Network Traffic Analysis Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"Data source: {source_name}", styles["BodyText"]),
        Paragraph(f"Packets analyzed: {len(df)}", styles["BodyText"]),
        Paragraph(f"Unique conversations: {df['connection'].nunique() if 'connection' in df else 0}", styles["BodyText"]),
        Paragraph(f"Potential review alerts: {len(alerts)}", styles["BodyText"]),
        Spacer(1, 14),
        Paragraph("Protocol distribution", styles["Heading2"]),
    ]
    counts = df["protocol"].value_counts().reset_index()
    counts.columns = ["Protocol", "Packets"]
    data = [["Protocol", "Packets"]] + counts.values.tolist()
    table = Table(data, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12334a")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),
        ("PADDING",(0,0),(-1,-1),6),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Interpretation", styles["Heading2"]))
    story.append(Paragraph(
        "Alerts indicate patterns that may deserve review. They are not proof of malicious activity. "
        "Validate findings against asset ownership, expected services, capture scope and known baselines.",
        styles["BodyText"]))
    doc.build(story)
    return buffer.getvalue()
