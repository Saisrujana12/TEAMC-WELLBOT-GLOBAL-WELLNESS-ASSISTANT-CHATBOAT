def calculate_bmi(weight, height):
    """
    Calculate BMI given weight (kg) and height (cm)
    """
    try:
        height_m = float(height) / 100
        weight_kg = float(weight)
        bmi = weight_kg / (height_m ** 2)
        return round(bmi, 2)
    except (ValueError, ZeroDivisionError):
        return 0

def analyze_wellness(bmi):
    """
    Analyze wellness based on BMI
    """
    if bmi < 18.5:
        return "Underweight", "Consider consulting a nutritionist to gain weight healthily."
    elif 18.5 <= bmi < 24.9:
        return "Normal Weight", "Great job! Maintain your current lifestyle."
    elif 25 <= bmi < 29.9:
        return "Overweight", "Incorporating more physical activity could be beneficial."
    else:
        return "Obese", "Please consult a healthcare provider for personalized advice."
