import datetime
from flask import Flask, render_template, request
from pymisp import PyMISP
import ollama
import traceback  # Import traceback module for detailed error logging

app = Flask(__name__)

MISP_URL = 'https://misp.unixfor.gr/events'
MISP_KEY = 'DTWbeIDzozljBFcgwTMNhvV7S6s8s35X3KLsu4WC'

misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False)

def format_misp_results(results):
    """Format MISP search results into a prompt for the model."""
    formatted_results = ""
    for result in results:
        formatted_results += f"Event ID: {result['Event']['id']}\n"
        formatted_results += f"Event Info: {result['Event']['info']}\n"
        formatted_results += f"Date: {result['Event']['date']}\n"
        formatted_results += "Tags: " + ', '.join(tag['name'] for tag in result['Event']['Tag']) + "\n"
        formatted_results += "-" * 20 + "\n"
    return formatted_results

def generate_report(ioc, formatted_results):
    """You have access to MISP database. Generate a report using the Ollama tinyllama model based on MISP search results."""
    prompt = f"""
    Write a detailed security report for the following Indicator of Compromise (IOC): {ioc}

    The following is the search result from the MISP database:
    {formatted_results}

    Include possible risks, attack patterns, and suggestions for mitigation if any.
    """
    
    try:
        # Call the Ollama API to generate a report
        response = ollama.generate(model="tinyllama", prompt=prompt)  # Adjusting to a hypothetical generate method
        
        # Log the response to inspect its structure
        print("Ollama response:", response)  # Inspect the full response
        
        # Check if the response is in the expected format
        if isinstance(response, dict) and 'response' in response and response['done']:
            return response['response']
        
        # Handle case where response is not as expected
        return "Unexpected response format. Please check the Ollama API."  # Adjusted message for clarity
    
    except Exception as e:
        # Capture detailed error messages for debugging
        return f"An error occurred while generating the report: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html', current_year=datetime.datetime.now().year)

@app.route('/search', methods=['POST'])
def search():
    ioc = request.form['ioc']
    try:
        # Search MISP for the IOC
        results = misp.search(value=ioc)
        if results:
            # Format results for model input
            formatted_results = format_misp_results(results)
            
            # Use Ollama to generate a report based on the search results
            report = generate_report(ioc, formatted_results)
            
            # Render the results and report on the results page
            return render_template('results.html', ioc=ioc, results=results, report=report, current_year=datetime.datetime.now().year)
        else:
            return render_template('results.html', ioc=ioc, results=None, report=None, current_year=datetime.datetime.now().year)
    except Exception as e:
        # Log the error with detailed traceback
        error_message = f"An error occurred: {e}\n{traceback.format_exc()}"
        print(error_message)  # Print to console or log to file
        return error_message  # Optionally return this to the user, or render an error template

if __name__ == "__main__":
    app.run(debug=True)
