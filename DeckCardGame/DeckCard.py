suits = ['♠', '♥', '♦', '♣']
cards = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']
values = [11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10]


deck = [(c, s, v) for c, v in zip(cards, values) for s in suits]

print(deck)