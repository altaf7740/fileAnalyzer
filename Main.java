package fileAnalyzer;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;

public class Main extends JFrame implements ActionListener {
	JFrame frame=new JFrame("File Analyzer");
	JTextField field;
	String filepath;
    JTabbedPane tab;  
	JButton Upload,select;
	JLabel aboutlabel;
	JPanel pannel2;

    Main(){
        tab  = new JTabbedPane(JTabbedPane.TOP);
		JPanel panel=new JPanel();
		pannel2 = new JPanel();	 
		pannel2.setLayout(null);
		aboutlabel = new JLabel();
		aboutlabel.setBounds(10,5,400,200);
		aboutlabel.setText("<html>File Analyzer is a forensic tool with Graphical User Interface that can be used to know the actual format of the file.<br/><br/>About the Developer :<br/><br/>follow me on Github : github.com/altaf7740<br/>follow me on Linkedin : linkedin.com/in/altaf7740<br/><br/><br/>Special Thanks To Rohit@GeekProCoder</html>"); 
		pannel2.add(aboutlabel);
        Upload=new JButton("Upload");
        Upload.addActionListener(this);
        select=new JButton("Select File");
        select.addActionListener(this);
        Upload.setBounds(100, 150, 210, 25);
        select.setBounds(320, 70, 120, 25);
        field=new JTextField();
        field.setBounds(20,70,300,25);
        field.setToolTipText("Enter File path");
        panel.add(field);
        panel.add(Upload);
        panel.add(select);
        panel.setLayout(null);
        tab.addTab("Home", panel);
        frame.setSize(450, 280);
		tab.addTab("About", pannel2);
        frame.add(tab);
        frame.setVisible(true);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane();
	}
		
	public static JPanel makePanel(String text) {
		JPanel pannel = new JPanel();
		pannel.add(new Label(text));
		pannel.setLayout(new GridLayout(2, 2));
		return pannel;
	}

	public void actionPerformed(ActionEvent e) {
		if(e.getSource()==select){    
			JFileChooser fileChooser=new JFileChooser();    
			int i=fileChooser.showOpenDialog(this);    
			if(i==JFileChooser.APPROVE_OPTION){
				File f=fileChooser.getSelectedFile(); 
				filepath=f.getPath();
				field.setText(filepath); 
			} 
		}               		
		if(e.getSource()==Upload) {
			try {
				filepath=field.getText();
				File file=new File(filepath);
				if(! file.exists()) 
					JOptionPane.showMessageDialog(this, "file not found");
				else{
					StringBuilder fileSignaure = File2Hex.convertToHex(file);
					String value = fileSignaure.toString();
					HexDataBase hexDBobj = new HexDataBase();
					hexDBobj.getfileInformation(value.trim());
					JOptionPane.showMessageDialog(this, "it is a "+hexDBobj.fileInformation+" file \n\nits extention is "+hexDBobj.fileExtention);
				}
			}

			catch(Exception ev) {
				JOptionPane.showMessageDialog(this, "unknown error occured");
			}
		
		}
	}

	public static void main(String[] args) {
		Main obj=new Main ();
	}
}