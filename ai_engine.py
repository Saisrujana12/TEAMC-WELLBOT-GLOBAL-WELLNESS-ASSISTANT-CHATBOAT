import google.generativeai as genai
import os

# Configure the API key
# Ideally, use an environment variable
API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_API_KEY_HERE") # Placeholder to avoid secret leak

def configure_ai():
    if API_KEY == "YOUR_API_KEY_HERE":
        print("WARNING: Gemini API Key not set. AI features will not work.")
        return False
    genai.configure(api_key=API_KEY)
    return True

def get_wellness_response(user_text, context=None):
    """
    Sends the user's text to Gemini and returns a wellness-focused response.
    """
    if not configure_ai():
        return "I am unable to connect to my brain right now. Please check my API Key settings."

    try:
        # Set up the model - Using 'gemini-flash-latest' as it has free tier access
        model = genai.GenerativeModel('gemini-flash-latest')

        # Create a system prompt to guide the AI's behavior
        system_prompt = """
        You are WellBot, a friendly and empathetic global wellness assistant. 
        Your goal is to provide helpful, general wellness advice, verify symptoms, and suggest healthy habits.
        
        IMPORTANT RULES:
        1. YOU ARE NOT A DOCTOR. Do not provide medical diagnoses or prescriptions.
        2. ALWAYS include a disclaimer effectively stating: "I am an AI, not a doctor. Please consult a healthcare professional for medical advice."
        3. If the user mentions severe symptoms (chest pain, difficulty breathing, suicidal thoughts), tell them to seek emergency help immediately.
        4. Keep responses concise (under 3-4 sentences) unless asked for more detail.
        5. Be encouraging and positive.
        
        User's Context: {context}
        User's Message: {user_text}
        """

        print(f"DEBUG: Sending to AI...") # Debug print
        # Generate content
        response = model.generate_content(system_prompt.format(context=context or "General Chat", user_text=user_text))
        
        print(f"DEBUG: AI Response received.") # Debug print
        return response.text
        
    except Exception as e:
        print(f"CRITICAL AI ERROR: {e}") # Make this very visible
        return f"I'm having trouble thinking right now. (Error: {str(e)})"
