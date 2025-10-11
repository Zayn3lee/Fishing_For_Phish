"""
Prepare Kaggle phishing dataset for Decision Tree training
"""
import pandas as pd
import os

print("=" * 80)
print("DATASET PREPARATION - DECISION TREE")
print("=" * 80)

# Find CSV file
print("\n🔍 Looking for phishing dataset CSV...")
csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and any(x in f.lower() for x in ['phishing', 'email'])]

if not csv_files:
    print("❌ No CSV found!")
    print("\n📥 Download from: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
    print("Save the CSV in this folder and run again.")
    exit(1)

csv_file = csv_files[0]
print(f"✅ Found: {csv_file}")

# Load dataset
print(f"\n📂 Loading dataset...")
df = pd.read_csv(csv_file, encoding='utf-8', on_bad_lines='skip')
print(f"✅ Loaded {len(df)} rows")

# Show columns
print(f"\n📊 Columns: {list(df.columns)}")

# Auto-detect columns or ask
text_col = None
label_col = None

for col in df.columns:
    if 'text' in col.lower() or 'body' in col.lower():
        text_col = col
    if 'type' in col.lower() or 'label' in col.lower():
        label_col = col

if not text_col or not label_col:
    print("\n⚙️  Manual column selection needed:")
    text_col = input("Enter email body/text column name: ").strip()
    label_col = input("Enter label/type column name: ").strip()
else:
    print(f"\n✅ Auto-detected columns:")
    print(f"   Body: {text_col}")
    print(f"   Label: {label_col}")

# Standardize
df_clean = df[[text_col, label_col]].copy()
df_clean.columns = ['body', 'label']
df_clean['subject'] = ""  # No subjects in this dataset

# Clean
df_clean = df_clean.dropna(subset=['body', 'label'])
df_clean = df_clean[df_clean['body'].astype(str).str.strip() != ""]

print(f"\n🧹 After cleaning: {len(df_clean)} rows")

# Show labels
print(f"\n📊 Label distribution:")
print(df_clean['label'].value_counts())

# Map labels to binary (1=phishing, 0=legitimate)
print(f"\n⚙️  Label mapping:")
unique_labels = df_clean['label'].unique()

if len(unique_labels) == 2:
    # Auto-detect
    label_list = list(unique_labels)
    if 'phishing' in str(label_list[0]).lower():
        phishing_label = label_list[0]
        legit_label = label_list[1]
    else:
        phishing_label = label_list[1]
        legit_label = label_list[0]
    print(f"   Phishing: {phishing_label}")
    print(f"   Legitimate: {legit_label}")
else:
    print("Available labels:", unique_labels)
    phishing_label = input("Which label is PHISHING? ").strip()
    legit_label = input("Which label is LEGITIMATE? ").strip()

# Convert to binary
df_clean['label'] = df_clean['label'].map({
    phishing_label: 1,
    legit_label: 0
})

# Remove any unmapped
df_clean = df_clean.dropna(subset=['label'])
df_clean['label'] = df_clean['label'].astype(int)

# Save
output_file = "emails_labeled.csv"
df_clean.to_csv(output_file, index=False)

print(f"\n💾 Saved to: {output_file}")
print(f"\n📊 Final dataset:")
print(f"   Total: {len(df_clean)}")
print(f"   Phishing: {sum(df_clean['label'] == 1)}")
print(f"   Legitimate: {sum(df_clean['label'] == 0)}")

# Show samples
print(f"\n📄 Sample phishing email:")
phishing_sample = df_clean[df_clean['label'] == 1].iloc[0]
print(f"   {phishing_sample['body'][:200]}...")

print(f"\n📄 Sample legitimate email:")
legit_sample = df_clean[df_clean['label'] == 0].iloc[0]
print(f"   {legit_sample['body'][:200]}...")

print("\n" + "=" * 80)
print("NEXT STEP: python extract_features.py")
print("=" * 80)