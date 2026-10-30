class Base:
    def base_m(self):
        return "base"


class Store(Base):
    def __init__(self, name):
        self.name = name

    def save(self):
        return super().base_m()

    def load(self):
        return self.save()

    @classmethod
    def make(cls):
        return cls.build()

    @classmethod
    def build(cls):
        return cls("built")


class Service:
    def __init__(self):
        self.store = Store("service")

    def run(self):
        return self.store.save()

    def deferred(self):
        def later():
            return self.run()

        return later
