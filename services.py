def dynamic_threshold(meter_type, historical_data):
    if meter_type == 'electricity' and historical_data:
        return sum(historical_data) / len(historical_data) * 1.2
    return 1800  # Default threshold