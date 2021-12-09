import abc


class Animal(metaclass=abc.ABCMeta):  # 同一类事物:动物
    @abc.abstractmethod
    def talk(self):
        pass


class People(Animal):  # 动物的形态之一:人
    def talk(self):
        print('say hello')


class Dog(Animal):  # 动物的形态之二:狗
    def talk(self):
        print('say wangwang')


class Pig(Animal):  # 动物的形态之三:猪
    def talk(self):
        print('say aoao')


# 定义一个统一的接口来访问
def func(object):
    object.talk()


if __name__ == "__main__":
    dog = Dog()
    pig = Pig()
    dog.talk()
    pig.talk()

    func(dog)
    func(pig)
    func(People())
