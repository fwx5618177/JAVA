import java.util.ArrayList;
import java.util.Collection;

public class ForDemo {
	public static void main(String[] args) {
		
		//�ַ�������
		String []str= {"zfliu","96"};
		
		for(String s:str) {
			System.out.println(s);
		}
		
		System.out.println("-------------------");
		
		//����
		Collection <String> c=new ArrayList <String>();
		c.add("zfliu");
		c.add("HelloWorld");
		for(String x : c) {
			System.out.println(x);
		}
		
		
	}
}
