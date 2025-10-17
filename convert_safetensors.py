# convert_safetensors.py
from transformers import BertForSequenceClassification, BertTokenizer
import torch

def convert_to_pytorch():
    """Convert .safetensors to .bin format"""
    print("🔄 Converting safetensors to pytorch format...")
    
    try:
        # Load from safetensors
        model = BertForSequenceClassification.from_pretrained("./it_support_model")
        tokenizer = BertTokenizer.from_pretrained("./it_support_model")
        
        # Save as pytorch format
        model.save_pretrained("./it_support_model", safe_serialization=False)
        print("✅ Converted to pytorch_model.bin format!")
        
    except Exception as e:
        print(f"❌ Conversion failed: {e}")

if __name__ == "__main__":
    convert_to_pytorch()