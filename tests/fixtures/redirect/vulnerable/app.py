class App:
    def handle_request(self, target):
        return (302, {"Location": target}, "Found")
