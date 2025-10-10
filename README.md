# Fishing_For_Phish
<img width="1919" height="656" alt="image" src="https://github.com/user-attachments/assets/be571cd9-c86e-4b61-aa14-36c31283e8bf" />
<i>Image 1: Home page of website</i>
<br>
<br>
<img width="1916" height="1026" alt="image" src="https://github.com/user-attachments/assets/f6a426e6-c853-4d11-a029-2b87b8905861" />
<i>Image 2: Auto Scanner of 10 most recent gmail account's emails</i>



## How to download the same dependencies required for the google credentials to work?
open <b>terminal</b> in the repository's directory and type in the following commands

[
<br/> python -m venv .venv
<br/> ./.venv/scripts/activate.bat
<br/> pip install -r requirements.txt
<br/>
]

This will create a python virtual environment and install the dependencies listed in the requirements.txt file. (similar to npm install and package.json for JavaScript applications).

Then add a <b>"client_secrets.json"</b> file to the overall project directory and paste the data of the gmail account. If you wanna test our application, msg us and we'll provide you with the test email's credentials.

If all setup correctly, open terminal and run the command <b>"python app.py"</b> to run the program. You will be brought to your web browser where you can login to the test gmail account using the username and password which will then fetch the data and display it in the console that you ran it from.

## 🤔 What is this?
A python-based web application that can auto scan your gmail account's emails and use both a rule-based checking system and Machine Learning techniques to detect phishing scams. It also allows you to manually upload your own email file to scan as well.

## 🧑‍🎓 Who are we?
We're a passionate group of aspiring IT professionals who were randomly assigned together, but are super excited to work together to make something worthy of an A!! 🤩🤩
