# Fishing_For_Phish
## How to download the same dependencies required for the google credentials to work?
open <b>terminal</b> in the repository's directory and type in the following commands

[
<br/> python -m venv .venv
<br/> ./.venv/scripts/activate.bat
<br/> pip install -r requirements.txt
<br/>
]

This will create a python virtual environment and install the dependencies listed in the requirements.txt file. (similar to npm install and package.json for JavaScript applications).

Then add a <b>"client_secrets.json"</b> file to the overall project directory and paste the data I sent.

If all setup correctly, when you run the <b>"get_data.py"</b> file, you should be brought to your web browser where you can login to the test gmail account using the username and password which will then fetch the data and display it in the console that you ran it from.

## 🤔 What is this?
A work-in-progress google chrome extension program that will automatically detect email phishing scams using advanced Machine Learning techniques, rule-based checks, adversarial emailt esting, malware attachment analysis, and so much more! Stay tuned to see what else we implement.

## 🧑‍🎓 Who are we?
We're a passionate group of aspiring IT professionals who were randomly assigned together, but are super excited to work together to make something worthy of an A!! 🤩🤩

## 🤡 Why is this ReadMe so cringe?
your mother lah. JK. Sometimes in life you need to enjoy the little things and make fun of the boring things. 
