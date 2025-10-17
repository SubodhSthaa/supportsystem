from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments
from datasets import load_dataset
import torch

# 1. Load dataset
dataset = load_dataset("csv", data_files={"train": "support_tickets.csv"})
label_mapping = {
    "hardware": 0,
    "software": 1,
    "network": 2,
    "password": 3,
    "digital_banking": 4,
    "loan": 5,
    "general": 6
}

def encode_labels(example):
    example["label"] = label_mapping[example["label"]]
    return example

dataset = dataset["train"].map(encode_labels)

# 2. Tokenize
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

def tokenize(batch):
    return tokenizer(batch["text"], padding="max_length", truncation=True, max_length=128)

dataset = dataset.map(tokenize, batched=True)
dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])

# 3. Split train/test
dataset = dataset.train_test_split(test_size=0.2)
train_ds = dataset["train"]
test_ds = dataset["test"]

# 4. Load model
model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=len(label_mapping))

# 5. Train
training_args = TrainingArguments(
    output_dir="./it_support_model",
    num_train_epochs=4,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    evaluation_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    logging_dir="./logs",
    load_best_model_at_end=True
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=test_ds,
)

trainer.train()

# 6. Save fine-tuned model
model.save_pretrained("./it_support_model")
tokenizer.save_pretrained("./it_support_model")

print("✅ Fine-tuned model saved to ./it_support_model")
