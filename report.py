import os

# Set allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    """
    Check if the file has an allowed extension.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def simulate_ocr(filename):
    """
    Simulated OCR function for Milestone 1.
    In a real app, this would use Tesseract or Google Cloud Vision.
    """
    # Simply return mock data based on the filename
    return {
        "filename": filename,
        "extracted_text": "Patient Name: John Doe\nTest: Full Blood Count\nResult: Haemoglobin 13.5 g/dL (Normal)",
        "summary": "Everything looks normal. Keep up the good work!"
    }
