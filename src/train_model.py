"""
Train Decision Tree model
"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

print("=" * 80)
print("DECISION TREE TRAINING")
print("=" * 80)

# Load features
print("\n📂 Loading features...")
df = pd.read_csv("features.csv")
print(f"✅ Loaded {len(df)} samples")

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']

print(f"\n📊 Dataset:")
print(f"   Features: {X.shape[1]}")
print(f"   Phishing: {sum(y == 1)} ({sum(y == 1)/len(y)*100:.1f}%)")
print(f"   Legitimate: {sum(y == 0)} ({sum(y == 0)/len(y)*100:.1f}%)")

# Split data
print("\n🔀 Splitting data (70% train, 30% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# Train Decision Tree
print("\n🌳 Training Decision Tree...")
model = DecisionTreeClassifier(
    max_depth=10,           # Limit depth to prevent overfitting
    min_samples_split=20,   # Require at least 20 samples to split
    min_samples_leaf=10,    # Require at least 10 samples per leaf
    random_state=42
)

model.fit(X_train, y_train)
print("✅ Training complete!")

# Evaluate
print("\n📈 EVALUATION:")
print("-" * 80)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.3f} ({accuracy*100:.1f}%)")

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"                 Predicted")
print(f"              Legit  Phishing")
print(f"Actual Legit   {cm[0][0]:5d}  {cm[0][1]:5d}")
print(f"    Phishing   {cm[1][0]:5d}  {cm[1][1]:5d}")

# Feature importance
print("\n🔍 TOP 10 MOST IMPORTANT FEATURES:")
print("-" * 80)

feature_importance = sorted(
    zip(X.columns, model.feature_importances_),
    key=lambda x: x[1],
    reverse=True
)

for i, (feature, importance) in enumerate(feature_importance[:10], 1):
    bar = "█" * int(importance * 50)
    print(f"{i:2d}. {feature:25} {importance:.4f} {bar}")

# Save model
print("\n💾 Saving model...")
model_data = {
    'model': model,
    'feature_names': list(X.columns),
    'model_type': 'decision_tree',
    'accuracy': accuracy
}

joblib.dump(model_data, 'phishing_model.pkl')
print("✅ Model saved to: phishing_model.pkl")

# Summary
print("\n" + "=" * 80)
print("TRAINING SUMMARY")
print("=" * 80)
print(f"✅ Decision Tree trained successfully")
print(f"📊 Accuracy: {accuracy*100:.1f}%")
print(f"🎯 Top feature: {feature_importance[0][0]}")
print(f"🌳 Tree depth: {model.get_depth()}")
print(f"🍃 Number of leaves: {model.get_n_leaves()}")
print(f"💾 Model ready to use")

print("\n" + "=" * 80)
print("NEXT STEP: python test_model.py")
print("=" * 80)