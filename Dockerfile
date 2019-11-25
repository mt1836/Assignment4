FROM ubuntu:19.10
COPY . /Assignment4
WORKDIR /Assignment4
RUN apt-get update
RUN apt-get install -y python3.7
RUN apt-get install -y python3-pip
RUN pip3 install flask
RUN pip3 install bcrypt
RUN pip3 install flask_sqlalchemy
RUN pip3 install flask_login
RUN pip3 install flask_wtf
CMD flask run --host=0.0.0.0

