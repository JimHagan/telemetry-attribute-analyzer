Here is the updated README file.

-----

# Log Ingest Attribute Analyzer

This Python script, `attribute-analyzer.py`, analyzes JSON or CSV log sample files to provide insights into log ingest patterns. It identifies key attributes for segmenting data, suggests attribute combinations for analysis, and flags potential high-volume anomalies.

This tool is intended to be run locally against a single JSON or CSV file containing an array of log objects.

## Dependencies

The script requires the following:

  * **Python 3.7+**
  * **pandas**: The only external Python library needed.

## Setup and Installation

It is highly recommended to run this script within a Python virtual environment to manage dependencies.

### 1\. Create a Virtual Environment

From your terminal, navigate to the directory where you saved `attribute-analyzer.py` and create a virtual environment:

```sh
# For macOS and Linux
python3 -m venv venv

# For Windows
python -m venv venv
```

### 2\. Activate the Virtual Environment

You must activate the environment in your terminal session before installing dependencies or running the script.

```sh
# For macOS and Linux
source venv/bin/activate

# For Windows (Command Prompt)
.\venv\Scripts\activate.bat

# For Windows (PowerShell)
.\venv\Scripts\Activate.ps1
```

Your terminal prompt should change to show `(venv)` at the beginning.

### 3\. Install Dependencies

With your virtual environment active, install the `pandas` library:

```sh
pip install pandas
```

## How to Run

Run the script from your terminal by passing the path to your JSON or CSV log sample file as an argument.

**Usage:**

```sh
python attribute-analyzer.py path/to/your-log-sample.csv
```

**Example:**

```sh
python attribute-analyzer.py "C:\Downloads\blackline-test--samples.json"
```

-----

## Interpreting the Output

The script will print its analysis directly to the terminal in four main sections, with status updates for long-running steps.

### Example Status Output

For large files, you will see status messages to show that the script is working:

```sh
--- Step 1/4: Loading Log File ---
  Detected JSON file. Reading file into memory...
  Loaded 25000 JSON objects. Normalizing into DataFrame...
  Normalizing column names (lowercase and stripping spaces)...
  Successfully loaded 25000 log entries.
--- File loaded in 0.28s ---

--- Step 2/4: Analyzing Attributes ---
  Analyzing attributes (this may take a moment on large files)...
  ...Attribute analysis complete (0.52s).

--- Step 3/4: Generating Summary Reports ---
(Report output is printed here)
--- Reports generated in 0.05s ---

--- Step 4/4: Analyzing Message Anomalies ---
  Starting message frequency analysis (this can be slow on large files)...
  Analyzing anomalies by grouping: ['message', 'level', 'container_name', 'namespace_name', 'plugin.source', 'environment']
  ...Message analysis complete (0.31s).

(Anomaly report is printed here)

------------------------------------------------------------
Analysis Complete.
------------------------------------------------------------
```

### 1\. Log Sample Count

This is the total number of log entries (JSON objects or CSV rows) found in the provided sample file.

```
### LOG SAMPLE COUNT: 25000 ###
```

### 2\. Attribute Analysis for Ingest Subdivision

This section lists the best attributes for "faceting" or "segmenting" your log data. An attribute is considered "best" if it meets two criteria:

  * **High Presence:** It appears on a high percentage of logs (default \> 40%).
  * **Low-to-Moderate Cardinality:** It has a small number of unique values (default \< 100).

This combination is ideal for creating dashboards and NRQL queries, as it groups logs without creating thousands of tiny, hard-to-read categories.

**Example Output:**

```
**newrelic.source**
    * **Presence:** 100.0% (25000 out of 25000 logs)
    * **Unique Values:** 2
    * **Examples:** "api.logs", "logs.APM"
```

### 3\. Attribute Combination Analysis

This section takes the top attributes from the previous analysis (default: 3) and combines them into a suggested NRQL query. This query is designed to give you a powerful, high-level breakdown of your log ingest across multiple dimensions.

**Example Output:**

````
The following combination of attributes provides a strong...
    1. **newrelic.source**
    2. **plugin.source**
    3. **operatingSystem**

#### Example NRQL Query ####

```nrql
SELECT count(*) FROM Log
FACET newrelic.source, plugin.source, operatingSystem
SINCE 1 HOUR AGO
````

### 4\. Potential Anomaly Insights

This section identifies and **classifies** the most frequent, repetitive log *combinations* (message + context) found in the sample. This is the single most effective way to find log-volume anomalies.

The script attempts to classify each anomaly:

  * **Potential Log Storm (Repetitive Error):** Often a component stuck in a retry loop (e.g., "failed to connect").
  * **Potential Low-Value Polling/Health Check:** Repetitive "OK" messages (e.g., "status requested," "no changes detected").
  * **Potential Verbose 'Chatter' Log:** High-frequency `INFO` logs that could be lowered to `DEBUG`.

**Example Output:**

```
**Anomaly #1**
    * **Count in Sample:** 4102 (16.4% of sample)
    * **Anomaly Type:** Potential Log Storm (Repetitive Error)
    * **Insight:** This indicates a component is likely stuck in a retry loop (e.g., cannot connect to a destination). Fixing the root cause will stop this log storm.
    * **Combination:**
        - message: "failed to publish events: temporary bulk send failure"
        - level: "error"
        - container_name: "metricbeat"
        - namespace_name: "elastic-system"
--------------------
**Anomaly #2**
    * **Count in Sample:** 3011 (12.0% of sample)
    * **Anomaly Type:** Potential Low-Value Polling/Health Check
    * **Insight:** This appears to be a repetitive 'check-in' or health check log. These are often safe to filter at the source or lower to a DEBUG level.
    * **Combination:**
        - message: "Status requested."
        - level: "info"
        - environment: "b02l01"
```