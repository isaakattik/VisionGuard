import os

from dotenv import load_dotenv

#Project Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
MODEL_PATH = os.path.join(BASE_DIR, "model", "scam_classifier_model.keras")

# Settings of Photos Process
IMG_SIZE = (224, 224)
SCAM_THRESHOLD = 0.75
LEGIT_THRESHOLD = 0.40

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") 

# Backwards compatibility alia

