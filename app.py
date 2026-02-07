"""
RNPS Mobile App - Flask Backend API with Authentication
Handles PDF generation for RNPS Record Sheets
Secure login with password hashing and JWT tokens
Production-ready version for Railway deployment
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import tempfile
import base64
from datetime import datetime, timedelta
from pdf_generator import generate_rnps_pdf
from PIL import Image
from io import BytesIO
import hashlib
import jwt
from functools import wraps
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# CORS Configuration - Update with your frontend domain
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Configuration
TEMPLATE_PDF = 'template_new.pdf'

# Security Configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable not set!")
    raise ValueError("SECRET_KEY must be set in environment variables")

ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')
if not ADMIN_PASSWORD_HASH:
    logger.error("ADMIN_PASSWORD_HASH environment variable not set!")
    raise ValueError("ADMIN_PASSWORD_HASH must be set in environment variables")

# JWT token expiry (8 hours)
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', '8'))

# Get environment
FLASK_ENV = os.environ.get('FLASK_ENV', 'production')


def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer TOKEN
            except IndexError:
                logger.warning("Invalid token format received")
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            logger.warning("Missing token in request")
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_data = data
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token used")
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    try:
        data = request.json
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'error': 'Password is required'}), 400
        
        # Hash the provided password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check if password matches
        if password_hash == ADMIN_PASSWORD_HASH:
            # Generate JWT token
            token = jwt.encode({
                'user': 'admin',
                'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
            }, SECRET_KEY, algorithm='HS256')
            
            logger.info("Successful login")
            
            return jsonify({
                'success': True,
                'token': token,
                'expires_in': TOKEN_EXPIRY_HOURS * 3600  # in seconds
            })
        else:
            logger.warning("Failed login attempt")
            return jsonify({'success': False, 'error': 'Invalid password'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Login failed'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'RNPS Backend Running',
        'template_exists': os.path.exists(TEMPLATE_PDF),
        'environment': FLASK_ENV
    })


@app.route('/api/generate-pdf', methods=['POST'])
@token_required  # Protect this route with authentication
def generate_pdf():
    """Generate RNPS PDF from form data"""
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('company_name'):
            return jsonify({'error': 'Company Name is required'}), 400
        if not data.get('vehicle_reg'):
            return jsonify({'error': 'Vehicle Registration is required'}), 400
        if not data.get('customer_name'):
            return jsonify({'error': 'Customer Name is required'}), 400
        
        # Decode signature from base64
        signature_image = None
        if data.get('signature_base64'):
            try:
                # Remove data URL prefix if present
                sig_data = data['signature_base64']
                if 'base64,' in sig_data:
                    sig_data = sig_data.split('base64,')[1]
                
                # Decode base64 to image
                sig_bytes = base64.b64decode(sig_data)
                signature_image = Image.open(BytesIO(sig_bytes))
            except Exception as e:
                logger.warning(f"Signature decode error: {e}")
                signature_image = None
        
        # Prepare data for PDF generation
        pdf_data = {
            'company_name': data.get('company_name', ''),
            'supplier_id': data.get('supplier_id', ''),
            'vehicle_reg': data.get('vehicle_reg', ''),
            'customer_name': data.get('customer_name', ''),
            'address': data.get('address', ''),
            'post_town': data.get('post_town', ''),
            'postcode': data.get('postcode', ''),
            'identity_codes': data.get('identity_codes', []),
            'entitlement_codes': data.get('entitlement_codes', []),
            'signature': signature_image,
            'sig_date': data.get('sig_date', datetime.now().strftime('%d/%m/%Y')),
            'print_name': data.get('print_name', ''),
        }
        
        # Generate filename
        vehicle_reg = data.get('vehicle_reg', 'Unknown').replace(' ', '').upper()
        customer_name = data.get('customer_name', 'Customer').replace(' ', '_')
        date_str = datetime.now().strftime('%Y%m%d')
        filename = f"RNPS_Record_{vehicle_reg}_{customer_name}_{date_str}.pdf"
        
        # Create temporary file
        temp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        output_path = temp_pdf.name
        temp_pdf.close()
        
        # Generate PDF
        if not os.path.exists(TEMPLATE_PDF):
            logger.error("Template PDF not found")
            return jsonify({'error': 'Template PDF not found. Please contact administrator.'}), 500
        
        generate_rnps_pdf(pdf_data, output_path, template_path=TEMPLATE_PDF)
        
        logger.info(f"PDF generated successfully: {filename}")
        
        # Send PDF file
        response = send_file(
            output_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
        # Clean up temp file after sending
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(output_path)
            except Exception as e:
                logger.warning(f"Failed to delete temp file: {e}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to generate PDF. Please try again.'}), 500


@app.route('/api/codes/identity', methods=['GET'])
def get_identity_codes():
    """Get list of identity proof codes"""
    codes = {
        'A': 'Driving Licence',
        'B': 'Utility, telephone or council tax bill',
        'C': 'A bank or building society statement',
        'D': 'Passport',
        'E': 'Foreign National Identity Card',
        'F': 'Debit or Credit Card',
        'G': 'A police warrant card',
        'H': 'An armed forces identity card',
    }
    return jsonify(codes)


@app.route('/api/codes/entitlement', methods=['GET'])
def get_entitlement_codes():
    """Get list of entitlement proof codes"""
    codes = {
        '1': 'Registration Certificate (V5C)',
        '2': 'Tear off slip V5C/2 section 10 of the V5C',
        '3': 'Certificate of entitlement to a mark (V750)',
        '4': 'Cherished transfer retention document (V778)',
        '5': 'Vehicle licence renewal form (V11)',
        '6': 'Temporary registration certificate (V379)',
        '7': 'Authorisation Certificate (V948) with Official DVLA stamp',
        '8': 'Letter of authorisation from Fleet Operators',
        '9': 'Record of insurer\'s name, reference and policy number',
    }
    return jsonify(codes)


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {str(error)}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("RNPS Mobile Backend Starting")
    logger.info(f"Environment: {FLASK_ENV}")
    logger.info("=" * 60)
    
    if not os.path.exists(TEMPLATE_PDF):
        logger.warning(f"⚠️  WARNING: {TEMPLATE_PDF} not found!")
        logger.warning(f"   Please copy your template PDF to: {os.path.abspath(TEMPLATE_PDF)}")
    else:
        logger.info(f"✅ Template PDF found: {TEMPLATE_PDF}")
    
    # Get port from environment (Railway sets this)
    port = int(os.environ.get('PORT', 5000))
    
    logger.info(f"\nServer running on port {port}")
    logger.info("\nPress CTRL+C to quit\n")
    logger.info("=" * 60)
    
    # For production, use gunicorn instead of app.run
    # This is just for local testing
    app.run(host='0.0.0.0', port=port, debug=(FLASK_ENV != 'production'))