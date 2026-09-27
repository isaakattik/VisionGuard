

import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
import keras
import tensorflow as tf
from config import MODEL_PATH, IMG_SIZE, SCAM_THRESHOLD, LEGIT_THRESHOLD

# Enabling graphics card memory expansion to avoid ("COM") errors
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except RuntimeError as e:
        print(f"GPU configuration error: {e}")

def load_cnn_model(model_path=MODEL_PATH):
    # Loading the saved ConvNeXtSmall model using Keras 3
    try:
        return keras.models.load_model(model_path)
    except Exception:
        return tf.keras.models.load_model(model_path)

def preprocess_image(image_path):
    #Preparing the screenshot and resizing it while maintaining the aspect ratio.    
    
    img = tf.io.read_file(image_path)
    img = tf.image.decode_image(img, channels=3, expand_animations=False)
    img = tf.image.resize_with_pad(img, IMG_SIZE[0], IMG_SIZE[1])
    img = tf.cast(img, tf.float32)
    return tf.expand_dims(img, axis=0)

def predict_visual_threat(model, image_path):
    #Calculating Probability and Applying the Decision Threshold    
    img_tensor = preprocess_image(image_path)
    logits = model(img_tensor, training=False)
    probability = float(tf.nn.sigmoid(logits).numpy()[0][0])
    
    if probability > SCAM_THRESHOLD:
        classification = "Scam"
        confidence = probability
    elif probability < LEGIT_THRESHOLD:
        classification = "Legit"
        confidence = 1.0 - probability
    else:
        classification = "Uncertain"
        confidence = max(probability, 1.0 - probability)
        
    return {
        "classification": classification,
        "confidence_score": confidence
    }
    
    