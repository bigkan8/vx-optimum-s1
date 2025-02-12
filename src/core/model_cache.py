import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from ..config.settings import MODEL_SETTINGS

class ModelCache:
    _instance = None
    _model = None
    _tokenizer = None
    
    @staticmethod
    def get_model():
        if ModelCache._model is None:
            settings = MODEL_SETTINGS["message_classifier"]
            name = settings["name"]
            path = settings["path"]  # This will be C:/Users/cyril/Downloads/optimum_model/optimum
            ModelCache._model = RobertaForSequenceClassification.from_pretrained(path)
            ModelCache._model.to(torch.device("cuda" if torch.cuda.is_available() else "cpu"))
            ModelCache._model.eval()
        return ModelCache._model
    
    @staticmethod
    def get_tokenizer():
        if ModelCache._tokenizer is None:
            settings = MODEL_SETTINGS["message_classifier"]
            ModelCache._tokenizer = RobertaTokenizer.from_pretrained(settings["path"])
        return ModelCache._tokenizer 