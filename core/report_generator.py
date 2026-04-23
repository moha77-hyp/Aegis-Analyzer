from fpdf import FPDF 
from datetime import datetime

class AegisReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Aegis Malware Anlysis Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(filename, pe_info, sections, yara_results, ml_prediction, output_path):
    pdf = AegisReport()
    pdf.add_page()

    pdf.set_font('arial', 'B', 12)
    pdf.cell(0, 10, f"Target File: {filename}", 0, 1)
    pdf.ln(5)

    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, "AI Engine Verdict:", 1, 1, 'L', True)
    pdf.set_font('Arial', '', 11)
    verdict = "Malicious" if ml_prediction['is_malware'] else "SAfe"
    confidence = ml_prediction['malware_probability'] if ml_prediction['is_malware'] else ml_prediction['safe_probability']
    pdf.cell(0, 10, f" - Decision: {verdict}", 0, 1)
    pdf.cell(0, 10, f" - Confidence: {confidence}%", 0, 1)
    pdf.ln(5)

    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, "YARA signature Scan:", 1, 1, 'L', True)
    pdf.set_font('Arial', '', 11)
    if yara_results:
        for res in yara_results:
            pdf.multi_cell(0, 10, f" * Rule: {res['rule_name']} | Severity: {res['severity']}\n Desc: {res['description']}")
    else:
        pdf.cell(0, 10, " * No malicious signatures detected.", 0, 1)
    pdf.ln(5)

    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, "PE Sections Analysis:", 1, 1, 'L', True)
    pdf.set_font('Courier', '', 9)

    pdf.cell(35, 10, "name", 1)
    pdf.cell(40, 10, "Raw Size", 1)
    pdf.cell(35, 10, "Entropy", 1)
    pdf.cell(35, 10, "Suspicious", 1, 1)

    for sec in sections:
        pdf.cell(35, 10, sec['name'], 1)
        pdf.cell(40, 10, str(sec['raw_size']), 1)
        pdf.cell(35, 10, str(round(sec['entropy'], 2)), 1)
        statues = "YES" if sec['is_suspicious'] else "NO"
        pdf.cell(35, 10,statues, 1, 1)

    pdf.output(output_path)
    return output_path