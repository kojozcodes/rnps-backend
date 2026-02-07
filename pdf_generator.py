"""
PDF Generator - Overlays form data and signature onto the RNPS template PDF
Mobile version using PIL Image instead of QImage
"""

import os
import tempfile
from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import black

# Page dimensions (A4)
PAGE_WIDTH = 595.15
PAGE_HEIGHT = 840.95


def convert_y(top_from_top):
    """Convert y coordinate from 'top from top of page' to reportlab's bottom-left origin"""
    return PAGE_HEIGHT - top_from_top


def save_pil_image_to_temp(pil_image):
    """Save PIL Image to temporary PNG file and return path"""
    if pil_image is None:
        return None
    
    temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    temp_path = temp_file.name
    temp_file.close()
    
    # Save PIL image
    pil_image.save(temp_path, 'PNG')
    
    return temp_path


def create_overlay_pdf(data, output_path):
    """Create a PDF overlay for the RNPS template"""
    c = canvas.Canvas(output_path, pagesize=(PAGE_WIDTH, PAGE_HEIGHT))
    c.setFont("Times-Roman", 12)
    c.setFillColor(black)
    
    # ===== COMPANY DETAILS SECTION =====
    company_name = data.get('company_name', '')
    if company_name:
        c.drawString(35, convert_y(137.5), company_name)
    
    supplier_id = data.get('supplier_id', '')
    if supplier_id:
        c.drawString(35, convert_y(187), supplier_id)
    
    vehicle_reg = data.get('vehicle_reg', '')
    if vehicle_reg:
        c.drawString(320, convert_y(187), vehicle_reg)
    
    # ===== CUSTOMER DETAILS SECTION =====
    customer_name = data.get('customer_name', '')
    if customer_name:
        c.drawString(140, convert_y(220), customer_name)
    
    address = data.get('address', '')
    if address:
        address_line = address.replace('\n', ', ')[:60]
        c.drawString(85, convert_y(242), address_line)
    
    post_town = data.get('post_town', '')
    if post_town:
        c.drawString(100, convert_y(283), post_town)
    
    postcode = data.get('postcode', '')
    if postcode:
        c.drawString(295, convert_y(283), postcode)
    
    # ===== PROOF CODES TABLE =====
    row_y_positions = [
        convert_y(633),   # Row 1 center
        convert_y(653),   # Row 2 center
        convert_y(673)    # Row 3 center
    ]
    
    identity_x = 35
    identity_serial_x = 158
    entitlement_x = 295
    entitlement_serial_x = 450
    
    c.setFont("Times-Roman", 12)
    
    # Write identity codes
    identity_codes = data.get('identity_codes', [])
    for i, (code, serial) in enumerate(identity_codes[:3]):  # Max 3 rows
        c.drawString(identity_x, row_y_positions[i], code)
        if serial:
            c.drawString(identity_serial_x, row_y_positions[i], serial[:18])
    
    # Write entitlement codes
    entitlement_codes = data.get('entitlement_codes', [])
    for i, (code, serial) in enumerate(entitlement_codes[:3]):  # Max 3 rows
        c.drawString(entitlement_x, row_y_positions[i], code)
        if serial:
            c.drawString(entitlement_serial_x, row_y_positions[i], serial[:18])
    
    # ===== SIGNATURE SECTION =====
    signature = data.get('signature')
    if signature:
        temp_path = save_pil_image_to_temp(signature)
        if temp_path:
            try:
                sig_y = convert_y(715)  # Slightly above the line
                c.drawImage(temp_path, 180, sig_y, width=120, height=40, 
                           preserveAspectRatio=True, mask='auto')
            except Exception as e:
                print(f"Error adding signature: {e}")
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
    
    # Date
    sig_date = data.get('sig_date', '')
    if sig_date:
        c.drawString(480, convert_y(710), sig_date)
    
    # Print Name
    print_name = data.get('print_name', '')
    if print_name:
        c.drawString(120, convert_y(748), print_name)
    
    c.save()
    return output_path


def generate_rnps_pdf(data, output_path, template_path):
    """Generate the RNPS Record Sheet PDF"""
    
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template PDF not found: {template_path}")
    
    # Read the template PDF
    template_reader = PdfReader(template_path)
    writer = PdfWriter()
    
    # Process each page (should be just 1 for RNPS)
    for template_page in template_reader.pages:
        # Create overlay for this page
        overlay_path = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False).name
        create_overlay_pdf(data, overlay_path)
        
        # Merge overlay onto template
        overlay_reader = PdfReader(overlay_path)
        if len(overlay_reader.pages) > 0:
            template_page.merge_page(overlay_reader.pages[0])
        
        writer.add_page(template_page)
        os.unlink(overlay_path)
    
    # Write the final PDF
    with open(output_path, 'wb') as output_file:
        writer.write(output_file)
    
    return output_path
