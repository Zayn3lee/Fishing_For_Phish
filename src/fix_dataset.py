# CSV Dataset Fixer - Run this BEFORE training your ML model
import pandas as pd
import os

def fix_dataset_format(input_file_path, output_file_path='fixed_training_data.csv'):
    """
    Fix any CSV dataset to work with your ML training code
    """
    print(f"Loading dataset from: {input_file_path}")
    
    try:
        # Try to load the CSV
        df = pd.read_csv(input_file_path)
        print(f"Loaded {len(df)} rows")
        print(f"Original columns: {list(df.columns)}")
        
        # Create the output dataframe with required columns
        fixed_df = pd.DataFrame()
        
        # Try to find subject column (optional)
        subject_cols = ['subject', 'Subject', 'SUBJECT', 'title', 'Title']
        subject_col = None
        for col in subject_cols:
            if col in df.columns:
                subject_col = col
                break
        
        if subject_col:
            fixed_df['subject'] = df[subject_col].fillna('').astype(str)
            print(f"Found subject column: {subject_col}")
        else:
            fixed_df['subject'] = ''  # Empty subjects
            print("No subject column found, using empty subjects")
        
        # Try to find body/text column (required)
        body_cols = ['body', 'Body', 'text', 'Text', 'message', 'Message', 
                    'email', 'Email', 'content', 'Content', 'Email Text', 'email_text']
        body_col = None
        for col in body_cols:
            if col in df.columns:
                body_col = col
                break
        
        if not body_col:
            raise ValueError(f"No text column found. Available columns: {list(df.columns)}")
        
        fixed_df['body'] = df[body_col].fillna('').astype(str)
        print(f"Found body column: {body_col}")
        
        # Try to find label column (required)
        label_cols = ['label', 'Label', 'spam', 'Spam', 'phishing', 'Phishing',
                     'class', 'Class', 'type', 'Type', 'Email Type', 'email_type']
        label_col = None
        for col in label_cols:
            if col in df.columns:
                label_col = col
                break
        
        if not label_col:
            raise ValueError(f"No label column found. Available columns: {list(df.columns)}")
        
        print(f"Found label column: {label_col}")
        print(f"Unique values in label column: {df[label_col].unique()}")
        
        # Convert labels to numeric (0 = legitimate, 1 = phishing)
        labels = df[label_col].astype(str).str.lower()
        
        # Define label mappings
        phishing_labels = ['spam', 'phishing', 'phishing email', 'malicious', 'bad', '1', 'true', 'yes']
        legitimate_labels = ['ham', 'legitimate', 'safe email', 'good', 'safe', '0', 'false', 'no']
        
        def convert_label(label):
            label = str(label).lower().strip()
            if label in phishing_labels:
                return 1
            elif label in legitimate_labels:
                return 0
            else:
                # Try to convert numeric
                try:
                    return int(float(label))
                except:
                    print(f"Warning: Unknown label '{label}', defaulting to 0")
                    return 0
        
        fixed_df['label'] = labels.apply(convert_label)
        
        # Remove rows with empty body
        fixed_df = fixed_df[fixed_df['body'].str.len() > 0]
        
        # Check final distribution
        label_counts = fixed_df['label'].value_counts()
        print(f"\nFinal dataset:")
        print(f"Total emails: {len(fixed_df)}")
        print(f"Legitimate emails (0): {label_counts.get(0, 0)}")
        print(f"Phishing emails (1): {label_counts.get(1, 0)}")
        
        if len(label_counts) < 2:
            print("WARNING: Only one class found! You need both phishing and legitimate emails.")
            return False
        
        # Save the fixed dataset
        fixed_df.to_csv(output_file_path, index=False)
        print(f"\nFixed dataset saved as: {output_file_path}")
        print("You can now use this file for ML training!")
        
        return True
        
    except Exception as e:
        print(f"Error processing dataset: {e}")
        return False

def create_test_dataset(output_file='test_dataset.csv'):
    """
    Create a small test dataset if nothing else works
    """
    print("Creating test dataset...")
    
    test_data = {
        'subject': [
            'URGENT: Account Verification',
            'Meeting tomorrow',
            'You won $1,000,000!',
            'Project update',
            'Click here NOW!',
            'Quarterly report',
            'Account suspended',
            'Lunch plans',
            'Free money offer',
            'Password reset'
        ] * 5,  # Repeat to get 50 emails
        
        'body': [
            'Your account will be suspended unless you verify immediately.',
            'Reminder about our meeting tomorrow at 3pm.',
            'Congratulations! You won our lottery. Send bank details.',
            'The project is progressing well. All tasks on schedule.',
            'Limited time offer! Click this link to claim your prize.',
            'Please review the attached quarterly financial report.',
            'Suspicious activity detected. Verify your account now.',
            'Want to grab lunch on Friday? Let me know.',
            'Easy money opportunity. No investment required.',
            'You requested a password reset. Click here to continue.'
        ] * 5,
        
        'label': [1, 0, 1, 0, 1, 0, 1, 0, 1, 0] * 5  # Alternating phishing/legitimate
    }
    
    df = pd.DataFrame(test_data)
    df.to_csv(output_file, index=False)
    
    print(f"Test dataset created: {output_file}")
    print(f"Total emails: {len(df)}")
    print(f"Phishing: {sum(df['label'])}, Legitimate: {len(df) - sum(df['label'])}")
    
    return True

# Example usage:
if __name__ == "__main__":
    print("CSV Dataset Fixer")
    print("=" * 50)
    
    # Option 1: Fix your existing dataset
    input_file = input("Enter path to your CSV file (or press Enter to create test dataset): ").strip()
    
    if input_file and os.path.exists(input_file):
        success = fix_dataset_format(input_file)
        if success:
            print("\nSUCCESS! Use 'fixed_training_data.csv' for ML training.")
        else:
            print("\nFailed to fix dataset. Creating test dataset instead...")
            create_test_dataset()
    else:
        if input_file:
            print(f"File not found: {input_file}")
        print("Creating test dataset...")
        create_test_dataset()
    
    print("\nNext steps:")
    print("1. Upload the generated CSV file to your ML training interface")
    print("2. Select 'CSV' training option (not ZIP)")
    print("3. Your ML model should train successfully!")