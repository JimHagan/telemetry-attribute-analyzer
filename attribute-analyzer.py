"""
Log Ingest Attribute Analyzer

Description:
This script loads a JSON or CSV log sample file, analyzes its contents,
and provides insights into log attributes and potential high-volume anomalies.

The script performs the following analyses:
1.  Total Log Count: Reports the exact number of log entries in the sample.
2.  Best Attribute Analysis: Identifies attributes with high presence (>40%) and
    low-to-moderate cardinality, making them ideal for segmentation.
3.  Combination Analysis: Suggests a combination of the "best" attributes
    to create a multi-dimensional facet in NRQL.
4.  Potential Anomaly Insights: Finds and *classifies* the most frequent,
    repetitive log *combinations* (message + context) to identify
    the true source of high-volume logs.

Required Dependencies:
-   pandas: This is the only external library required.
    You can install it using pip:
    pip install pandas

Usage:
Save this file as 'attribute-analyzer.py' and run it from your terminal,
passing the path to your log sample file as an argument.

Example:
    python attribute-analyzer.py path/to/your-log-sample.csv
    python attribute-analyzer.py path/to/your-log-sample.json

"""

import json
import argparse
import pandas as pd
from collections import Counter
import os  # For file extension checking
import time # For status messages

# --- Analysis Configuration ---

# Threshold for an attribute to be considered "high presence"
PRESENCE_THRESHOLD_PCT = 40.0

# Upper limit for "low-to-moderate" cardinality. Filters out high-variance
# fields like trace IDs, message IDs, or raw messages.
CARDINALITY_UPPER_LIMIT = 100

# The number of attributes to use in the "best combination" NRQL.
BEST_COMBO_COUNT = 6

# The number of high-frequency messages to show in the anomaly report.
TOP_ANOMALOUS_MESSAGES = 5

# Attributes to explicitly ignore in all analyses (all lowercase).
# These are often high-cardinality fields with no grouping value.
ATTRIBUTES_TO_IGNORE = [
    'timestamp', 
    'messageid', 
    'newrelic.logpattern'
]


# --- Helper & Printing Functions ---

def print_header(title):
    """Prints a formatted section header."""
    print("\n" + ("-" * 60))
    print(f"### {title.upper()} ###")
    print(("-" * 60) + "\n")

def _dedup_names(names):
    """
    Robustly de-duplicates a list of names, appending .1, .2, etc.
    This replaces the internal pandas `_maybe_dedup_names`.
    """
    names = list(names)
    counts = {}
    for i, name in enumerate(names):
        if name in counts:
            counts[name] += 1
            names[i] = f"{name}.{counts[name] - 1}"
        else:
            counts[name] = 1
    return names

def load_log_file(filepath):
    """
    Loads the log file (JSON or CSV) into a pandas DataFrame.
    """
    # Status message is printed from main()
    df = None # Initialize df
    try:
        # Get file extension
        _root, file_ext = os.path.splitext(filepath)
        file_ext = file_ext.lower()

        if file_ext == '.json':
            print("  Detected JSON file. Reading file into memory...")
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"  Loaded {len(data)} JSON objects. Normalizing into DataFrame...")
            if not isinstance(data, list):
                print("  Error: Expected a JSON array (a list of log objects).")
                return None
            
            # Normalize the JSON (handles nested objects if any)
            df = pd.json_normalize(data)

        elif file_ext == '.csv':
            print("  Detected CSV file. Reading file into DataFrame...")
            # --- MODIFICATION: Removed 'mangle_dupe_cols' ---
            # This argument was removed in pandas 2.0+ and the
            # behavior (mangling) is now default.
            df = pd.read_csv(filepath) 
            # --- END MODIFICATION ---
            
            if df.empty:
                print("  Warning: CSV file is empty.")

        else:
            print(f"  Error: Unsupported file type '{file_ext}'. "
                  "Only .json and .csv files are supported.")
            return None
        
        # --- Normalize all column names ---
        if df is None or df.empty:
            print("  Warning: File loaded, but no data was found.")
            return df # Return the empty dataframe
        
        print("  Normalizing column names (lowercase and stripping spaces)...")
        df.columns = df.columns.str.lower().str.strip()
        
        # --- FIX for Duplicated Normalized Columns ---
        if df.columns.has_duplicates:
            print("  Found columns that are duplicates after normalization.")
            print("  Renaming duplicates (e.g., 'level.1', 'level.2')...")
            df.columns = _dedup_names(df.columns)
        # --- END FIX ---
        
        print(f"  Successfully loaded {len(df)} log entries.")
        return df

    except FileNotFoundError:
        print(f"  Error: File not found at '{filepath}'")
        return None
    except json.JSONDecodeError:
        print("  Error: Could not decode JSON. File may be corrupt or not valid JSON.")
        return None
    except pd.errors.ParserError:
        print(f"  Error: Could not parse CSV. File may be malformed.")
        return None
    except UnicodeDecodeError:
        print("  Error: Could not read file due to a UnicodeDecodeError. "
              "Please ensure the file is UTF-8 encoded.")
        return None
    except Exception as e:
        print(f"  An unexpected error occurred during file loading: {e}")
        return None

def analyze_attributes(df):
    """
    Analyzes each attribute (column) in the DataFrame for presence,
    cardinality, and examples.
    """
    print("  Analyzing attributes (this may take a moment on large files)...")
    start_time = time.time()
    total_logs = len(df)
    attribute_stats = []

    # load_log_file guarantees unique columns
    for col in df.columns:
        # Check base name (e.g., 'level' for 'level.1')
        base_col = col.split('.')[0]
        if col in ATTRIBUTES_TO_IGNORE or base_col in ATTRIBUTES_TO_IGNORE:
            continue
        
        col_data = df[col]
        non_null_count = col_data.count()

        if non_null_count == 0:
            continue

        presence_pct = (non_null_count / total_logs) * 100
        unique_values = col_data.nunique()
        examples = col_data.dropna().unique()[:5]
        
        attribute_stats.append({
            "attribute": col,
            "presence_count": non_null_count,
            "presence_pct": presence_pct,
            "unique_values": unique_values,
            "examples": list(examples)
        })

    # Sort by presence (descending), then unique values (ascending)
    sorted_stats = sorted(attribute_stats,
                          key=lambda x: (-x['presence_pct'], x['unique_values']))
    
    end_time = time.time()
    print(f"  ...Attribute analysis complete ({end_time - start_time:.2f}s).")
    return total_logs, sorted_stats

def print_best_attributes(total_logs, sorted_stats):
    """
    Prints the formatted analysis for the "Best Attributes" section.
    """
    print_header(f"Log Sample Count: {total_logs}")

    print_header("Attribute Analysis for Ingest Subdivision")
    print(f"Finding attributes with > {PRESENCE_THRESHOLD_PCT}% presence "
          f"and < {CARDINALITY_UPPER_LIMIT} unique values.")

    best_attributes = []
    found_attributes = False

    for item in sorted_stats:
        # Filter for attributes that are good candidates for subdivision
        if (item['presence_pct'] >= PRESENCE_THRESHOLD_PCT and
            item['unique_values'] > 1 and
            item['unique_values'] <= CARDINALITY_UPPER_LIMIT):

            found_attributes = True
            best_attributes.append(item['attribute'])

            print("\n" + ("-" * 20))
            print(f"**{item['attribute']}**")
            print(f"    * **Presence:** {item['presence_pct']:.1f}% "
                  f"({item['presence_count']} out of {total_logs} logs)")
            print(f"    * **Unique Values:** {item['unique_values']}")
            
            # Format examples for clean printing
            example_str = ", ".join([f'"{str(e)}"' for e in item['examples']])
            print(f"    * **Examples:** {example_str}")

    if not found_attributes:
        print("\nNo attributes met the high-presence/low-cardinality criteria.")

    return best_attributes

def print_combination_analysis(best_attributes):
    """
    Prints the combination analysis and a sample NRQL query.
    """
    print_header("Attribute Combination Analysis")

    if not best_attributes:
        print("No best attributes found, skipping combination analysis.")
        return

    # Select the top N attributes for the combination
    combo_attributes = best_attributes[:BEST_COMBO_COUNT]
    
    print(f"The following {len(combo_attributes)} attributes provide a strong, "
          "multi-dimensional breakdown of log ingest based on the sample:")
    for i, attr in enumerate(combo_attributes, 1):
        print(f"    {i}. **{attr}**")

    print("\n#### Example NRQL Query ####")
    print("Use this query in New Relic to see your log counts faceted "
          "by this combination:")
    
    # Need to quote attributes that have a '.'
    facet_list = [f"`{attr}`" if '.' in attr else attr for attr in combo_attributes]
    facet_string = ", ".join(facet_list)
    
    nrql_query = f"SELECT count(*) FROM Log \nFACET {facet_string} \nSINCE 1 HOUR AGO"
    print("\n```nrql\n" + nrql_query + "\n```")

def infer_anomaly_type(message, level):
    """
    Analyzes the message and level to classify the anomaly.
    Returns (anomaly_type, insight_description)
    """
    message_lower = str(message).lower()
    level_lower = str(level).lower()

    # --- Type 1: Repetitive Error / Failure ---
    error_keywords = ['failed', 'failure', 'error', 'exception', 'cannot connect', 'temporary bulk send failure']
    if level_lower in ['error', 'warn', 'fatal', 'critical'] or any(kw in message_lower for kw in error_keywords):
        return (
            "Potential Log Storm (Repetitive Error)",
            "This indicates a component is likely stuck in a retry loop (e.g., cannot "
            "connect to a destination). Fixing the root cause will stop this log storm."
        )

    # --- Type 2: Repetitive "OK" / Polling ---
    polling_keywords = ['health', 'status requested', 'skipping patch', 'no status changes', 'check-in', 'success', 'started call', 'finished call']
    if any(kw in message_lower for kw in polling_keywords) and level_lower in ['info', 'n/a', 'debug']:
        return (
            "Potential Low-Value Polling/Health Check",
            "This appears to be a repetitive 'check-in' or health check log. "
            "These are often safe to filter at the source or lower to a DEBUG level."
        )
    
    # --- Type 3: Verbose Informational Log ---
    # This is the catch-all for high-frequency info/debug logs
    if level_lower in ['info', 'debug', 'n/a']:
        return (
            "Potential Verbose 'Chatter' Log",
            "This is a high-frequency informational log. It may be logging a common "
            "action on every request or loop, which can often be sampled or lowered in severity."
        )
    
    # --- Fallback ---
    return (
        "High-Frequency Combination",
        "The specific reason is unclear, but this combination of attributes "
        "and message is extremely frequent in the sample and warrants investigation."
    )

def print_anomaly_insights(df, top_n):
    """
    Finds and prints the most frequent, repetitive log messages
    combined with other key contextual attributes.
    """
    print_header("Potential Anomaly Insights")
    
    print("  Starting message frequency analysis (this can be slow on large files)...")
    start_time = time.time()

    # --- Use an explicit "good list" of attributes ---
    PREFERRED_CONTEXT_ATTRIBUTES = [
        # Severity
        'level', 'log.level', 'severity',
        
        # Source
        'logger', 'logger_name', 'filepath', 'file.path', 'plugin.source',

        # K8s / Container
        'container_name', 'namespace_name', 'pod_name', 'cluster_name',

        # Application / Service
        'app', 'app.name', 'application', 'application.name', 'appName',
        'service', 'service.name', 'serviceName',
        'entity.name', 'entity.type',
        
        # Environment / Host
        'env', 'environment',
        'host', 'hostname',
        
        # Team / Owner
        'team', 'team.name', 'owner'
    ]

    # All columns are normalized, so just check for 'message'
    if 'message' not in df.columns:
        print("  Cannot perform anomaly analysis: 'message' column not found.")
        print(f"  Available columns are: {list(df.columns)}")
        return

    # Find which context attributes are present in the df
    group_by_cols = ['message']
    
    # Iterate over all available columns in the dataframe
    for col in df.columns:
        if col == 'message':
            continue
        # Only add the column if it's in our preferred list
        if col in PREFERRED_CONTEXT_ATTRIBUTES:
            group_by_cols.append(col)

    print(f"  Analyzing anomalies by grouping: {group_by_cols}")

    try:
        analysis_df = df[group_by_cols].copy()
        
        # Convert message to string and strip whitespace
        analysis_df['message'] = analysis_df['message'].astype(str).str.strip()
        
        # Fill NaN in context columns so they are grouped as 'N/A'
        for col in group_by_cols:
            if col != 'message':
                analysis_df[col] = analysis_df[col].fillna('N/A')

        combination_counts = analysis_df.groupby(group_by_cols).size()
        top_combinations = combination_counts.sort_values(ascending=False)

    except Exception as e:
        print(f"  An error occurred during anomaly grouping: {e}")
        return

    if top_combinations.empty:
        print("  No message combinations found to analyze for anomalies.")
        return
    
    end_time = time.time()
    print(f"  ...Message analysis complete ({end_time - start_time:.2f}s).")

    print(f"\nShowing the Top {top_n} most frequent log *combinations* in the sample.\n"
          "Repetitive combinations are the strongest indicators of high log volume.\n")

    for i, (combination, count) in enumerate(top_combinations.head(top_n).items(), 1):
        
        print(f"**Anomaly #{i}**")
        print(f"    * **Count in Sample:** {count} "
              f"({(count / len(df) * 100):.1f}% of sample)")
        
        # --- Anomaly Classification ---
        message = "N/A"
        level = "N/A"
        
        if isinstance(combination, tuple):
            # Create a dict from the combination for easy lookup
            combo_dict = dict(zip(group_by_cols, combination))
            message = combo_dict.get('message', "N/A")
            
            # Find the level, checking for 'level' or other common names
            level_key = next((k for k in combo_dict if k in ['level', 'log.level', 'severity']), None)
            if level_key:
                level = combo_dict[level_key]

        else:
             # Case for only 'message'
             message = combination
        
        anomaly_type, anomaly_desc = infer_anomaly_type(message, level)
        
        print(f"    * **Anomaly Type:** {anomaly_type}")
        print(f"    * **Insight:** {anomaly_desc}")
        # --- END ---

        print("    * **Combination:**")
        
        if isinstance(combination, tuple):
            for col_name, value in zip(group_by_cols, combination):
                value_str = str(value)
                if len(value_str) > 150: # Truncate long messages
                    value_str = value_str[:150] + "..."
                print(f"        - {col_name}: \"{value_str}\"")
        else:
             value_str = str(combination)
             if len(value_str) > 150:
                 value_str = value_str[:150] + "..."
             print(f"        - message: \"{value_str}\"")

        print("-" * 20)


# --- Main Execution ---

def main():
    """
    Main function to parse arguments and run the analyses.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Analyzes a JSON or CSV log sample file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog='attribute-analyzer.py'  # Set the program name
    )
    parser.add_argument(
        'filepath',
        metavar='<your_log_file.json_or_csv>',
        type=str,
        help='The path to the JSON or CSV log file to analyze.'
    )

    args = parser.parse_args()
    
    print("\n--- Step 1/4: Loading Log File ---")
    start_load = time.time()
    df = load_log_file(args.filepath)
    if df is None or df.empty:
        print("\nExiting due to file loading error or empty file.")
        return
    end_load = time.time()
    print(f"--- File loaded in {end_load - start_load:.2f}s ---")
    

    print("\n--- Step 2/4: Analyzing Attributes ---")
    total_logs, sorted_stats = analyze_attributes(df)
    
    print("\n--- Step 3/4: Generating Summary Reports ---")
    start_report = time.time()
    best_attributes = print_best_attributes(total_logs, sorted_stats)
    print_combination_analysis(best_attributes)
    end_report = time.time()
    print(f"--- Reports generated in {end_report - start_report:.2f}s ---")
    
    print("\n--- Step 4/4: Analyzing Message Anomalies ---")
    print_anomaly_insights(df, TOP_ANOMALOUS_MESSAGES)


    print("\n" + ("-" * 60))
    print("Analysis Complete.")
    print(("-" * 60) + "\n")


if __name__ == "__main__":
    main()