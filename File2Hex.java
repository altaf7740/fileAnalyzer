package fileAnalyzer;
import java.io.*;

public class File2Hex
{
    public static StringBuilder convertToHex(File file) throws IOException {
	InputStream is = new FileInputStream(file);
	int value = 0, loop = 0;
	StringBuilder sbHex = new StringBuilder();
	//logic to get hex of the file
	while (loop < 8) {
		value = is.read();
	    //convert to hex value with "X" formatter
        sbHex.append(String.format("%02X ", value));
		++loop;
	   }
	is.close();
	return sbHex;
    }

   public static void main(String[] args) throws IOException
   {
    	//display output to console
		StringBuilder hexStore = convertToHex(new File("/home/king/Pictures/2nd.png"));
		System.out.println(hexStore);
    }
}