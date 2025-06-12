#!/usr/bin/env python3
"""
Nessus DOCX Report Generator - Flask Web Application

Main Flask application providing web interface for converting Nessus XML files
to formatted DOCX reports.
"""

import os
import logging
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash

# Import our custom modules
from modules.nessus_parser import NessusParser
from modules.docx_generator import DocxGenerator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'nessus-docx-generator-secret-key-change-in-production'

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DOWNLOAD_FOLDER'] = 'downloads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit
app.config['ALLOWED_EXTENSIONS'] = {'nessus', 'xml'}

# Ensure directories exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['DOWNLOAD_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# Initialize processors
nessus_parser = NessusParser()
docx_generator = DocxGenerator()


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def cleanup_old_files():
    """Clean up old uploaded and generated files (older than 2 minutes - AGGRESSIVE)"""
    import time
    current_time = time.time()
    two_minutes_ago = current_time - 120  # 2 minutes in seconds (reduced from 10 minutes)
    
    for folder in [app.config['UPLOAD_FOLDER'], app.config['DOWNLOAD_FOLDER']]:
        try:
            if not os.path.exists(folder):
                continue
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path) and not filename.startswith('.'):
                    file_time = os.path.getmtime(file_path)
                    if file_time < two_minutes_ago:
                        os.remove(file_path)
                        logger.info(f"AGGRESSIVE cleanup - removed old file: {file_path}")
        except Exception as e:
            logger.warning(f"Error cleaning up files in {folder}: {e}")


def cleanup_all_files():
    """Clean up ALL files in upload and download folders immediately - ZERO PERSISTENCE"""
    files_removed = 0
    for folder in [app.config['UPLOAD_FOLDER'], app.config['DOWNLOAD_FOLDER']]:
        try:
            if not os.path.exists(folder):
                continue
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path) and not filename.startswith('.'):
                    os.remove(file_path)
                    files_removed += 1
                    logger.info(f"ZERO PERSISTENCE - removed file: {file_path}")
        except Exception as e:
            logger.warning(f"Error cleaning up files in {folder}: {e}")
    
    if files_removed > 0:
        logger.info(f"ZERO PERSISTENCE CLEANUP: Removed {files_removed} files total")
    else:
        logger.debug("No files to clean up - server is clean")


@app.route('/')
def index():
    """Main page with upload form"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    """Handle file upload and report generation"""
    try:
        # Clean up old files first
        cleanup_old_files()
        
        # Check if file was provided
        if 'nessus_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['nessus_file']
        
        # Check if file was actually selected
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        # Validate file type
        if not file or not allowed_file(file.filename):
            flash('Invalid file type. Please upload a .nessus or .xml file.', 'error')
            return redirect(url_for('index'))
        
        # Secure filename and save
        original_filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())[:8]
        upload_filename = f"{unique_id}_{original_filename}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], upload_filename)
        
        # Ensure upload directory exists and is writable
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Try to create a test file to check permissions
        test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], '.permission_test')
        try:
            with open(test_file_path, 'w') as test_file:
                test_file.write('test')
            os.remove(test_file_path)
        except (PermissionError, OSError) as e:
            logger.error(f"Upload directory permission test failed: {e}")
            flash('Upload directory permissions error. Please check Docker container setup.', 'error')
            return redirect(url_for('index'))
        
        try:
            file.save(upload_path)
        except PermissionError as e:
            logger.error(f"Permission error saving file to {upload_path}: {e}")
            flash('Permission error: Unable to save uploaded file. Please check directory permissions.', 'error')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error saving file to {upload_path}: {e}")
            flash(f'Error saving file: {str(e)}', 'error')
            return redirect(url_for('index'))
        logger.info(f"File uploaded: {upload_path}")
        
        # Get form data
        customer_abbreviation = request.form.get('customer_abbreviation', '').strip().upper()
        network_type = request.form.get('network_type', 'external')
        include_informational = 'include_informational' in request.form
        
        # Validate customer abbreviation
        if not customer_abbreviation:
            flash('Customer abbreviation is required', 'error')
            return redirect(url_for('index'))
        
        logger.info(f"Customer abbreviation: {customer_abbreviation}")
        logger.info(f"Network type: {network_type}")
        logger.info(f"Include informational vulnerabilities: {include_informational}")
        
        # Parse Nessus file and immediately clean up
        try:
            logger.info("Starting Nessus file parsing...")
            parsed_data = nessus_parser.parse_nessus_file(upload_path)
            summary_stats = nessus_parser.get_summary_stats(parsed_data)
            
            # IMMEDIATELY delete uploaded file after parsing - no persistence
            if os.path.exists(upload_path):
                os.remove(upload_path)
                logger.info(f"IMMEDIATELY deleted uploaded file after parsing: {upload_path}")
            
            logger.info(f"Parsed {len(parsed_data)} hosts with {summary_stats['total_vulnerabilities']} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error parsing Nessus file: {e}")
            flash(f'Error parsing Nessus file: {str(e)}', 'error')
            # Clean up uploaded file on error
            if os.path.exists(upload_path):
                os.remove(upload_path)
                logger.info(f"Cleaned up uploaded file after error: {upload_path}")
            return redirect(url_for('index'))
        
        # Generate DOCX report
        try:
            logger.info("Starting DOCX report generation...")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f"Nessus_Report_{timestamp}_{unique_id}.docx"
            report_path = os.path.join(app.config['DOWNLOAD_FOLDER'], report_filename)
            
            docx_generator.generate_report(parsed_data, summary_stats, report_path, 
                                         include_informational=include_informational,
                                         customer_abbreviation=customer_abbreviation,
                                         network_type=network_type)
            logger.info(f"Report generated: {report_path}")
            
        except Exception as e:
            logger.error(f"Error generating DOCX report: {e}")
            flash(f'Error generating report: {str(e)}', 'error')
            # Clean up uploaded file
            if os.path.exists(upload_path):
                os.remove(upload_path)
            return redirect(url_for('index'))
        
        # Upload file already cleaned up after parsing - no action needed
        logger.debug("Upload file already cleaned up after parsing - maintaining zero persistence")
        
        # Success - redirect to download
        flash('Report generated successfully!', 'success')
        return render_template('index.html', 
                             success=True, 
                             generated_filename=report_filename)
        
    except Exception as e:
        logger.error(f"Unexpected error in upload handler: {e}")
        flash(f'An unexpected error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/download/<filename>')
def download(filename):
    """Serve generated DOCX files for download and delete after serving"""
    try:
        # Security check - ensure filename is safe
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            logger.warning(f"Attempted to download unsafe filename: {filename}")
            flash('Invalid file request', 'error')
            return redirect(url_for('index'))
        
        # Check if file exists
        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            logger.warning(f"Requested file not found: {file_path}")
            flash('File not found', 'error')
            return redirect(url_for('index'))
        
        logger.info(f"Serving file for download: {filename}")
        
        # Create a response with the file
        response = send_from_directory(
            app.config['DOWNLOAD_FOLDER'], 
            filename, 
            as_attachment=True,
            download_name=f"nessus_vulnerability_report_{datetime.now().strftime('%Y%m%d')}.docx"
        )
        
        # Immediately delete file after serving (aggressive cleanup)
        @response.call_on_close
        def delete_file():
            try:
                # Delete the specific downloaded report file immediately
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"IMMEDIATELY deleted downloaded file: {file_path}")
                
                # Clean up ALL files in both uploads and downloads folders
                cleanup_all_files()
                logger.info("AGGRESSIVE cleanup: Removed all upload and download files after user download")
                
            except Exception as e:
                logger.warning(f"Could not delete files during cleanup: {e}")
        
        # Also schedule a backup cleanup in case the above fails
        import threading
        def backup_cleanup():
            import time
            time.sleep(2)  # Wait 2 seconds then force cleanup
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                cleanup_all_files()
                logger.info("Backup cleanup completed - no files should remain")
            except Exception as e:
                logger.warning(f"Backup cleanup failed: {e}")
        
        cleanup_thread = threading.Thread(target=backup_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        return response
        
    except Exception as e:
        logger.error(f"Error serving download: {e}")
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash("File is too large. Maximum size is 100MB.", 'error')
    return redirect(url_for('index'))


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {e}")
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('index'))


@app.route('/cleanup')
def manual_cleanup():
    """Manual cleanup route for testing"""
    try:
        cleanup_all_files()
        flash('All files cleaned up successfully!', 'success')
    except Exception as e:
        flash(f'Error during cleanup: {str(e)}', 'error')
    return redirect(url_for('index'))


def start_periodic_cleanup():
    """Start a background thread for periodic aggressive cleanup"""
    import threading
    import time
    
    def periodic_cleanup():
        while True:
            try:
                time.sleep(60)  # Run every 1 minute
                cleanup_old_files()
                logger.debug("Periodic cleanup completed - ensuring zero persistence")
            except Exception as e:
                logger.warning(f"Periodic cleanup error: {e}")
    
    cleanup_thread = threading.Thread(target=periodic_cleanup)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    logger.info("Started periodic cleanup thread - runs every 60 seconds")


if __name__ == '__main__':
    # Create necessary directories with proper permissions
    import stat
    for folder in ['uploads', 'downloads', 'static', 'templates']:
        try:
            os.makedirs(folder, exist_ok=True)
            # Set directory permissions to be writable (for Linux containers)
            if folder in ['uploads', 'downloads']:
                os.chmod(folder, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 777 permissions
        except Exception as e:
            logger.warning(f"Could not create or set permissions for {folder}: {e}")
    
    # Clean up any existing files on startup
    logger.info("ZERO PERSISTENCE STARTUP: Cleaning up existing files...")
    cleanup_all_files()
    
    # Start periodic cleanup to ensure no files persist
    start_periodic_cleanup()
    
    # Production server settings
    import os
    debug_mode = os.environ.get('FLASK_ENV', 'production') != 'production'
    port = int(os.environ.get('PORT', 1881))
    host = os.environ.get('HOST', '0.0.0.0')
    
    logger.info(f"Starting KPMG-PFCG Pentest Finding Card Generator on {host}:{port}")
    logger.info(f"Debug mode: {debug_mode}")
    
    app.run(
        debug=debug_mode,
        host=host,
        port=port
    ) 