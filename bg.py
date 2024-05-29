#!/usr/bin/env python3
import pandas as pd
from pathlib import Path


file_dict: dict = {
        '.csv': pd.read_csv,
        '.json': pd.read_json
        }

test = '/home/jonny/Downloads/passwords.csv'

file_suffix = Path(test).suffix
print(file_suffix)

reader = file_dict.get(file_suffix)

df = reader(test)

print(df)
