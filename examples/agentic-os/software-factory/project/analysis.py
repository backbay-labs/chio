def moving_average(values, window):
    """Average a sequence over complete sliding windows."""
    return [sum(values[max(0, i-window+1):i+1]) / window
            for i in range(len(values))]
