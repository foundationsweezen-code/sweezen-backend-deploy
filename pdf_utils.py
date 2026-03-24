"""PDF generation utilities for Sweezen Foundation"""
import io
import base64
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF
from reportlab.graphics.barcode import code128
from reportlab.graphics.barcode import qr as qr_code
from num2words import num2words
from datetime import datetime

NAVY = colors.HexColor('#071828')
GOLD = colors.HexColor('#F59E0B')
GREEN = colors.HexColor('#1B6B3A')
GRAY = colors.HexColor('#64748B')
LIGHT_BG = colors.HexColor('#F8FAFC')

def get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='EagleTitle', fontName='Helvetica-Bold', fontSize=18, textColor=NAVY, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name='EagleSubtitle', fontName='Helvetica', fontSize=10, textColor=GOLD, alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name='EagleHeading', fontName='Helvetica-Bold', fontSize=13, textColor=NAVY, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name='EagleBody', fontName='Helvetica', fontSize=10, textColor=colors.black, leading=14))
    styles.add(ParagraphStyle(name='EagleSmall', fontName='Helvetica', fontSize=8, textColor=GRAY, leading=10))
    styles.add(ParagraphStyle(name='EagleRight', fontName='Helvetica', fontSize=10, textColor=colors.black, alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name='EagleCenter', fontName='Helvetica', fontSize=10, textColor=colors.black, alignment=TA_CENTER))
    return styles

def add_header(elements, styles, title="Sweezen Foundation"):
    elements.append(Paragraph("SWEEZEN FOUNDATION", styles['EagleTitle']))
    elements.append(Paragraph("Section 8 Non-Profit | CIN: U85300XX2020NPL000000", styles['EagleSubtitle']))
    elements.append(Paragraph("Registered Office: India | PAN: AACTS1234A | 12A: AACTS1234AF2020 | 80G: AACTS1234AG2020", styles['EagleSmall']))
    elements.append(HRFlowable(width="100%", thickness=2, color=GOLD, spaceAfter=12, spaceBefore=6))

def generate_80g_receipt_pdf(donation):
    """Generate 80G tax receipt PDF for a donation"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=20*mm, rightMargin=20*mm)
    styles = get_styles()
    elements = []

    # Header
    add_header(elements, styles)
    elements.append(Paragraph("80G DONATION RECEIPT", ParagraphStyle(name='ReceiptTitle', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=16, spaceBefore=8)))

    # Receipt details table
    receipt_data = [
        ['Receipt Number:', donation.get('receipt_number', 'N/A'), 'Date:', datetime.fromisoformat(donation.get('created_at', datetime.now().isoformat())).strftime('%d %B %Y')],
    ]
    t = Table(receipt_data, colWidths=[90, 180, 50, 150])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), NAVY),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    # Donor details
    elements.append(Paragraph("DONOR DETAILS", styles['EagleHeading']))
    donor_data = [
        ['Name:', donation.get('donor_name', 'N/A')],
        ['Email:', donation.get('donor_email', 'N/A')],
        ['Phone:', donation.get('donor_phone', 'N/A')],
        ['PAN:', donation.get('donor_pan', 'N/A')],
    ]
    t2 = Table(donor_data, colWidths=[80, 400])
    t2.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), GRAY),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 12))

    # Donation details
    elements.append(Paragraph("DONATION DETAILS", styles['EagleHeading']))
    amount = donation.get('amount', 0)
    amount_words = num2words(int(amount), lang='en_IN').title() + " Rupees Only"
    tax_saved = int(amount * 0.3)

    donation_table_data = [
        ['Donation Amount:', f'INR {amount:,.2f}'],
        ['Amount in Words:', amount_words],
        ['Donation Type:', 'Recurring Monthly' if donation.get('is_recurring') else 'One-Time'],
        ['Payment ID:', donation.get('payment_id', 'N/A')],
        ['Project:', donation.get('project_name', 'General Fund')],
        ['Payment Mode:', 'Razorpay' if donation.get('razorpay_mode') else 'Online'],
    ]
    t3 = Table(donation_table_data, colWidths=[120, 360])
    t3.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), GRAY),
        ('TEXTCOLOR', (1, 0), (1, 0), GREEN),
        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (1, 0), (1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t3)
    elements.append(Spacer(1, 16))

    # Tax Benefit Box
    elements.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))
    tax_data = [
        ['80G Tax Benefit', f'Estimated Tax Saved: INR {tax_saved:,} (at 30% tax bracket)'],
    ]
    t4 = Table(tax_data, colWidths=[120, 360])
    t4.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, 0), NAVY),
        ('TEXTCOLOR', (1, 0), (1, 0), GREEN),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(t4)
    elements.append(Spacer(1, 20))

    # Certification
    elements.append(Paragraph("CERTIFICATION", styles['EagleHeading']))
    cert_text = (
        "This is to certify that Sweezen Foundation (Section 8 Company) has received the above-mentioned "
        "donation. The Foundation is registered under Section 12A of the Income Tax Act, 1961 and is approved "
        "under Section 80G. Donors are eligible for tax deduction under Section 80G of the Income Tax Act, 1961. "
        "All donations are subject to applicable tax laws."
    )
    elements.append(Paragraph(cert_text, styles['EagleBody']))
    elements.append(Spacer(1, 30))

    # Signature area
    sig_data = [
        ['', ''],
        ['_________________________', '_________________________'],
        ['Authorized Signatory', 'Foundation Seal'],
        ['Sweezen Foundation', ''],
    ]
    t5 = Table(sig_data, colWidths=[240, 240])
    t5.setStyle(TableStyle([
        ('FONTNAME', (0, 2), (-1, 3), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (-1, -1), GRAY),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t5)

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=6))
    elements.append(Paragraph("This is a computer-generated receipt and does not require a physical signature.", styles['EagleSmall']))
    elements.append(Paragraph("For queries: careers@sweezen.org | +91-9876543210 | www.sweezen.org", styles['EagleSmall']))

    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_csr1_report_pdf(report_data):
    """Generate CSR-1 compliance report PDF"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=15*mm, rightMargin=15*mm)
    styles = get_styles()
    elements = []

    # Header
    add_header(elements, styles)
    elements.append(Paragraph("CSR-1 COMPLIANCE REPORT", ParagraphStyle(name='CSR1Title', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=4)))
    elements.append(Paragraph(f"Financial Year: {report_data.get('financial_year', '2024-25')}", ParagraphStyle(name='FYText', fontName='Helvetica', fontSize=10, textColor=GOLD, alignment=TA_CENTER, spaceAfter=16)))

    # Summary
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", styles['EagleHeading']))
    summary_data = [
        ['Total Projects', str(report_data.get('total_projects', 0))],
        ['Total Funds Raised', f"INR {report_data.get('total_raised', 0):,.0f}"],
        ['Total Donations Received', str(report_data.get('total_donations', 0))],
        ['CSR Partners', str(report_data.get('total_partners', 0))],
        ['Total CSR Committed', f"INR {report_data.get('total_committed', 0):,.0f}"],
        ['Total CSR Utilized', f"INR {report_data.get('total_utilized', 0):,.0f}"],
        ['Utilization Rate', f"{report_data.get('utilization_rate', 0):.1f}%"],
        ['Report Generated', datetime.now().strftime('%d %B %Y')],
    ]
    t = Table(summary_data, colWidths=[180, 370])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), NAVY),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 16))

    # Category Breakdown
    elements.append(Paragraph("2. CATEGORY-WISE EXPENDITURE", styles['EagleHeading']))
    cat_header = ['Category', 'Projects', 'Budget (INR)', 'Raised (INR)', 'Beneficiaries']
    cat_rows = [cat_header]
    for cat, info in report_data.get('category_breakdown', {}).items():
        cat_rows.append([
            cat.capitalize(),
            str(info.get('projects', 0)),
            f"{info.get('budget', 0):,.0f}",
            f"{info.get('raised', 0):,.0f}",
            f"{info.get('beneficiaries', 0):,}",
        ])
    t2 = Table(cat_rows, colWidths=[100, 60, 120, 120, 100])
    t2.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 16))

    # SDG Alignment
    elements.append(Paragraph("3. UN SDG ALIGNMENT", styles['EagleHeading']))
    sdg_data = [['SDG Goal', 'Focus Area']]
    for sdg, area in report_data.get('sdg_alignment', {}).items():
        sdg_data.append([sdg, area])
    t3 = Table(sdg_data, colWidths=[150, 400])
    t3.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), GREEN),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t3)
    elements.append(Spacer(1, 16))

    # Partner Details
    if report_data.get('partners'):
        elements.append(Paragraph("4. CSR PARTNER DETAILS", styles['EagleHeading']))
        partner_header = ['Company', 'Tier', 'Committed (INR)', 'Utilized (INR)', 'Rate']
        partner_rows = [partner_header]
        for p in report_data['partners']:
            util_rate = round((p.get('funds_utilized', 0) / p.get('funds_committed', 1)) * 100, 1) if p.get('funds_committed') else 0
            partner_rows.append([
                p.get('company_name', ''),
                p.get('tier', '').capitalize(),
                f"{p.get('funds_committed', 0):,.0f}",
                f"{p.get('funds_utilized', 0):,.0f}",
                f"{util_rate}%",
            ])
        t4 = Table(partner_rows, colWidths=[130, 60, 110, 110, 60])
        t4.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (2, 0), (-1, -1), 'RIGHT'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ]))
        elements.append(t4)

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))
    elements.append(Paragraph("This report is auto-generated by Sweezen Foundation's CSR Compliance System.", styles['EagleSmall']))
    elements.append(Paragraph("For verification: careers@sweezen.org | FCRA Registration | NGO Darpan | CSR-1 Compliant", styles['EagleSmall']))
    elements.append(Spacer(1, 16))

    sig_data = [
        ['_________________________', '_________________________'],
        ['CSR Committee Chairman', 'Foundation Director'],
    ]
    t5 = Table(sig_data, colWidths=[260, 260])
    t5.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (-1, -1), GRAY),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t5)

    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_donation_report_pdf(donations, stats):
    """Generate admin donation report PDF"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm, leftMargin=12*mm, rightMargin=12*mm)
    styles = get_styles()
    elements = []

    add_header(elements, styles)
    elements.append(Paragraph("DONATION SUMMARY REPORT", ParagraphStyle(name='DonTitle', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=16)))

    # Summary stats
    summary = [
        ['Total Donations', str(stats.get('count', 0))],
        ['Total Amount', f"INR {stats.get('total', 0):,.0f}"],
        ['Average Donation', f"INR {stats.get('avg', 0):,.0f}"],
        ['Report Date', datetime.now().strftime('%d %B %Y')],
    ]
    ts = Table(summary, colWidths=[150, 400])
    ts.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), NAVY), ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6), ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(ts)
    elements.append(Spacer(1, 12))

    # Donations table
    header = ['Donor', 'Email', 'Amount', 'Status', 'Date', 'Receipt']
    rows = [header]
    for d in donations[:50]:
        rows.append([
            d.get('donor_name', '')[:20], d.get('donor_email', '')[:25],
            f"INR {d.get('amount', 0):,.0f}", d.get('status', '').capitalize(),
            datetime.fromisoformat(d.get('created_at', datetime.now().isoformat())).strftime('%d/%m/%Y'),
            d.get('receipt_number', '')[:15]
        ])
    t = Table(rows, colWidths=[80, 110, 70, 55, 65, 90])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4), ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    elements.append(t)

    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=6))
    elements.append(Paragraph("Generated by Sweezen Foundation Admin Panel", styles['EagleSmall']))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def _image_from_data_url(data_url: str):
    if not data_url or not isinstance(data_url, str):
        return None
    if not data_url.startswith("data:image/"):
        return None
    parts = data_url.split(",", 1)
    if len(parts) != 2:
        return None
    try:
        decoded = base64.b64decode(parts[1])
        return io.BytesIO(decoded)
    except Exception:
        return None


def generate_volunteer_id_card_pdf(card_record, volunteer, logo_path=None):
    """Generate volunteer identity card PDF with profile info, QR code, and barcode."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=12 * mm, bottomMargin=12 * mm, leftMargin=12 * mm, rightMargin=12 * mm)
    styles = get_styles()
    elements = []

    details = card_record.get("personal_details", {})
    generated = card_record.get("generated_card", {})
    card_id = card_record.get("card_id", "PENDING")
    verify_url = generated.get("verify_url", "")

    add_header(elements, styles)
    elements.append(Paragraph("VOLUNTEER IDENTITY CARD", ParagraphStyle(name='VIC_Title', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=10)))

    if logo_path:
        logo = Path(logo_path)
        if logo.exists():
            try:
                brand = Image(str(logo), width=35 * mm, height=35 * mm)
                elements.append(Table([[brand]], colWidths=[186 * mm], style=TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                ])))
            except Exception:
                pass

    photo_stream = _image_from_data_url(details.get("photo_data_url", ""))
    photo_cell = Paragraph("No Photo", styles['EagleCenter'])
    if photo_stream:
        try:
            photo_cell = Image(photo_stream, width=30 * mm, height=30 * mm)
        except Exception:
            photo_cell = Paragraph("Photo Error", styles['EagleCenter'])

    profile_data = [
        ["Card ID", card_id],
        ["Name", details.get("full_name", volunteer.get("name", "Volunteer"))],
        ["DOB", details.get("date_of_birth", "")],
        ["Phone", details.get("phone", volunteer.get("phone", ""))],
        ["Address", details.get("address", "")],
        ["Education", details.get("education", "")],
        ["Valid Until", generated.get("valid_until", "")[:10]],
        ["Status", card_record.get("card_status", "pending").upper()],
    ]
    profile_table = Table(profile_data, colWidths=[35 * mm, 90 * mm])
    profile_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))

    front_table = Table([
        [photo_cell, profile_table]
    ], colWidths=[38 * mm, 125 * mm])
    front_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1.2, NAVY),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(front_table)
    elements.append(Spacer(1, 8))

    qr_value = verify_url or f"SWEEZEN:{card_id}"
    qr_widget = qr_code.QrCodeWidget(qr_value)
    bounds = qr_widget.getBounds()
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    qr_size = 35 * mm
    qr_drawing = Drawing(qr_size, qr_size, transform=[qr_size / width, 0, 0, qr_size / height, 0, 0])
    qr_drawing.add(qr_widget)

    qr_flowable = renderPDF.GraphicsFlowable(qr_drawing)
    barcode_flowable = code128.Code128(card_id, barHeight=14 * mm, barWidth=0.5)

    back_table = Table([
        [Paragraph("Scan to Verify", styles['EagleCenter']), Paragraph("Volunteer Code", styles['EagleCenter'])],
        [qr_flowable, barcode_flowable],
        [Paragraph(qr_value[:90], styles['EagleSmall']), Paragraph(card_id, styles['EagleCenter'])],
    ], colWidths=[70 * mm, 93 * mm])
    back_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1.2, NAVY),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(back_table)

    elements.append(Spacer(1, 10))
    elements.append(Paragraph("This card is generated by Sweezen Foundation and intended for identity verification only.", styles['EagleSmall']))

    doc.build(elements)
    buffer.seek(0)
    return buffer
