# check_evil.py — taruh di root project
import pandas as pd

df = pd.read_csv('data/raw/labelled_training_data.csv')
print('Total rows   :', len(df))
print('Total evil=1 :', df['evil'].sum())

if df['evil'].sum() > 0:
    first_evil = df[df['evil'] == 1].index[0]
    last_evil  = df[df['evil'] == 1].index[-1]
    print('First evil=1 at row:', first_evil)
    print('Last evil=1 at row :', last_evil)
else:
    print('Tidak ada evil=1 di file ini — coba file CSV lain di folder yang sama.')