package com.glearning.students.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.glearning.students.model.Student;

@Repository
public interface StudentRepository extends JpaRepository<Student, Integer>{

}
