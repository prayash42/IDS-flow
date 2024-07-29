import pickle
import numpy as np

def load_model(model_path='C:/1D/Projects/IDS/random_forest_IDS_model.pkl'):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    return model

def make_predictions(features, model):
    features_array = np.array([list(f.values()) for f in features])
    predictions = model.predict(features_array)
    return predictions
