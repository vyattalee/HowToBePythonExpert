from collections import namedtuple

Card = namedtuple("Card", ["rank", "suit"])

cards = []
for suit in "\u2660", "\u2665", "\u2666", "\u2663":
    for rank in "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K":
        cards.append(Card(rank, suit))

print(cards)