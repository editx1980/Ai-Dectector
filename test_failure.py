def calculate_total(price: float, quantity: int) -> float:
    return price * quantity


def test_calculate_total():
    result = calculate_total(10, 5)

    assert result == 50