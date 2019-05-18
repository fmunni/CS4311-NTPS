
#Author: fmunni
#dependencies
#Pthon: python3 with anaconda
#scapy: pip install --pre scapy[complete]

from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import os

root = Tk()
root.title('Network Traffic Proxy System')
root.geometry("1000x700")
#root.resizable(0, 0)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=10)

# option view
optionView = Frame(root, background="#DADADA", height=590)
optionView.grid(row=0, column=0, sticky="nsew", padx=2)
optionView.columnconfigure(0, weight=1)

# content view
contentView = Frame(root, background="lightgray", height=50)
contentView.grid(row=0, column=1, sticky="nsew", padx=2)


def clearContentView():
    list = contentView.grid_slaves()
    for l in list:
        l.destroy()

def livePacketView():

    from scapy.all import sniff, wrpcap, rdpcap, hexdump, raw
    clearContentView();
    # all the ui elements to be reused
    packetDisplay = Text(contentView, height=20, width=100, bg="lightgray")
    scrollbar = Scrollbar(contentView)
    pktsListbox = Listbox(contentView, width=80, yscrollcommand=scrollbar.set)

    sniffStatusString = StringVar()
    sniffStatus = Label(
        contentView, textvariable=sniffStatusString, bg="lightgray")

    # content view title
    Label(contentView, text='Live Packet View', bg="lightblue").grid(
        row=0, columnspan=10, sticky="nsew")

    Label(contentView, text='Proxy Behavior', bg="lightgray").grid(
        row=1, column=0, sticky="nsew")
    proxyBehavior = StringVar(contentView)
    proxyBehavior.set("Disabled")  # default value
    OptionMenu(contentView, proxyBehavior, "Disabled", "Enabled").grid(
        row=1, column=1, sticky="nsew")

    Label(contentView, text='Interception Behavior', bg="lightgray").grid(
        row=1, column=2, sticky="nsew")
    interceptBehavior = StringVar(contentView)
    interceptBehavior.set("Disabled")  # default value
    OptionMenu(contentView, interceptBehavior, "Disabled", "Enabled").grid(
        row=1, column=3, sticky="nsew")

    Label(contentView, text='Queue Size', bg="lightgray").grid(
        row=1, column=4, sticky="nsew")
    queueSize = StringVar(contentView)
    queueSize.set(5)  # default value
    OptionMenu(contentView, queueSize, 5, 20, 50, 100, 200).grid(
        row=1, column=5, sticky="nsew")

    # second row
    row = 2
    livepkts = []

    def doLiveSniff():
        sniffStatusString.set("Sniffing live pkts. Please wait...")
        pktsListbox.delete(0, END)
        root.update()
        qsize = int(queueSize.get())
        print("QUEUE size: ", qsize)
        pkts = sniff(count=qsize,)
        for pkt in pkts:
            pktsListbox.insert(END, pkt.summary())
            livepkts.append(pkt)
        sniffStatusString.set("Sniffing done!")

    Button(contentView, text="Sniff live packet", width=20, command=doLiveSniff).grid(
        row=row, column=0, columnspan=2, sticky="w", pady=10, padx=2)

    sniffStatus.grid(row=row, column=2, columnspan=3, sticky="w")

    row += 1
    Label(contentView, text='List of live packets:', bg="lightgray").grid(
        row=row, column=0, columnspan=10, sticky="w")

    def curSelect(event):
        packetDisplay.delete(1.0, END)
    pktsListbox.bind('<<ListboxSelect>>', curSelect)

    row += 1
    pktsListbox.grid(row=row, column=0, columnspan=8, padx=5)
    scrollbar.grid(row=row, column=8, sticky="w")
    scrollbar.config(command=pktsListbox.yview)

    row += 1

    def savePacketsAsPCAP():
        if len(livepkts) == 0:
            messagebox.showinfo("Save", "Packet list is empty.")
            return
        else:
            if not os.path.isdir("./pcap"):
                os.mkdir("./pcap")
            nf = len(os.listdir("./pcap/"))
            wrpcap("./pcap/live{}.pcap".format(nf), livepkts)
            messagebox.showinfo("Save", "Saved successfully.")
    Button(contentView, text="Save packets as PCAP", width=20, command=savePacketsAsPCAP).grid(
        row=row, column=5, columnspan=3, sticky="w", padx=2, pady=2)
    row += 1
    Label(contentView, text='Packet view area:', bg="lightgray").grid(
        row=row, column=0, columnspan=10, sticky="w")

    def showdump(dumptype):
        packetDisplay.delete('1.0', END)
        if len(pktsListbox.curselection()) == 0:
            print("Please select a packet!")
            packetDisplay.insert(END, "Please select a packet!")
            return
        selectedPktIdx = pktsListbox.curselection()[0]
        pkt = livepkts[selectedPktIdx]
        dissectString = str(pkt)
        if dumptype == "dissected":
            dissectString = pkt.show(dump=True)
        elif dumptype == "hex":
            dissectString = hexdump(pkt, dump=True)

        packetDisplay.insert(END, dissectString)

    row += 1
    Button(contentView, text="Dissected", width=8, command=lambda: showdump("dissected")).grid(
        row=row, column=0, sticky="w", padx=2)
    Button(contentView, text="Binary", width=8, command=lambda: showdump("binary")).grid(
        row=row, column=1, sticky="w")
    Button(contentView, text="HEX", width=8, command=lambda: showdump("hex")).grid(
        row=row, column=2, sticky="w")

    row += 1
    packetDisplay.grid(row=row, columnspan=10, sticky="w")

    print("live packet view!")



def pcapPacketView():
    from scapy.all import sniff, rdpcap,hexdump
    clearContentView()
    # all the ui elements to be reused
    packetDisplay = Text(contentView, height=20, width=100, bg="lightgray")
    scrollbar = Scrollbar(contentView)
    pktsListbox = Listbox(contentView, width=80, yscrollcommand=scrollbar.set)

    # content view title
    Label(contentView, text='PCAP Packet View', bg="lightblue").grid(
        row=0, columnspan=10, sticky="nsew")
    row=1
    Label(contentView, text='PCAP file', bg="lightgray").grid(
        row=row, column=0, sticky="w",pady=2)
    pcapfilepath = Text(contentView, height=1, width=80, bg="lightgray")
    pcapfilepath.grid(row=row,column=1,columnspan=8,pady=2,sticky="w");

    livepkts = []

    def doSniffFromPCAP(filepath):
        
        pktsListbox.delete(0, END)
        root.update()
        
        pkts = sniff(offline=filepath)
        for pkt in pkts:
            pktsListbox.insert(END, pkt.summary())
            livepkts.append(pkt)
       

    def openFile():
        filepath =  filedialog.askopenfilename(initialdir = "./pcap",title = "Select file",filetypes = (("PCAP files","*.pcap"),("all files","*.*")))
        #print(filepath);
        pcapfilepath.delete('1.0', END)
        pcapfilepath.insert(END,filepath)
        doSniffFromPCAP(filepath);

    Button(contentView, text="Open", width=8, command=openFile).grid(
        row=row, column=9, sticky="w",padx=2,pady=2)

    # row+=1;
    # sniffStatus.grid(row=row, column=2, columnspan=3, sticky="w")

    row += 1
    Label(contentView, text='List of live packets:', bg="lightgray").grid(
        row=row, column=0, columnspan=10, sticky="w")

    def curSelect(event):
        packetDisplay.delete(1.0, END)
    pktsListbox.bind('<<ListboxSelect>>', curSelect)

    row += 1
    pktsListbox.grid(row=row, column=0, columnspan=8, padx=5)
    scrollbar.grid(row=row, column=8, sticky="w")
    scrollbar.config(command=pktsListbox.yview)
    #packet view area
    row += 1
    Label(contentView, text='Packet view area:', bg="lightgray").grid(
        row=row, column=0, columnspan=10, sticky="w")

    def showdump(dumptype):
        packetDisplay.delete('1.0', END)
        if len(pktsListbox.curselection()) == 0:
            print("Please select a packet!")
            packetDisplay.insert(END, "Please select a packet!")
            return
        selectedPktIdx = pktsListbox.curselection()[0]
        pkt = livepkts[selectedPktIdx]
        dissectString = str(pkt)
        if dumptype == "dissected":
            dissectString = pkt.show(dump=True)
        elif dumptype == "hex":
            dissectString = hexdump(pkt, dump=True)

        packetDisplay.insert(END, dissectString)

    row += 1
    Button(contentView, text="Dissected", width=8, command=lambda: showdump("dissected")).grid(
        row=row, column=0, sticky="w", padx=2)
    Button(contentView, text="Binary", width=8, command=lambda: showdump("binary")).grid(
        row=row, column=1, sticky="w")
    Button(contentView, text="HEX", width=8, command=lambda: showdump("hex")).grid(
        row=row, column=2, sticky="w")

    row += 1
    packetDisplay.grid(row=row, columnspan=10, sticky="w")
    print("PCAP Packet view")


Label(optionView, text='Option View', bg="lightblue").grid(row=0,  sticky="nsew")

Button(optionView, text="Live packet", width=15,
       command=livePacketView).grid(row=1, pady=5)
Button(optionView, text="Packet from PCAP", width=15,
       command=pcapPacketView).grid(row=2, pady=5)
#Button(optionView, text="Hook Collection", width=15).grid(row=3, pady=5)


root.mainloop()
