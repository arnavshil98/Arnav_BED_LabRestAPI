package com.glearning.students.service;

import java.util.List;

import com.glearning.students.model.Student;


public interface StudentService {

	public List<Student> findAll();

	public Student findById(int theId);

	public Student save(Student thestudent);

	public void deleteById(int theId);

	

}